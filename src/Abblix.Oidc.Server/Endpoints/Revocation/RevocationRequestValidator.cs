// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.RateLimiting;
using Abblix.Jwt;
using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;


namespace Abblix.Oidc.Server.Endpoints.Revocation;

/// <summary>
/// Validates revocation requests in accordance with OAuth 2.0 standards.
/// This class is responsible for ensuring that revocation requests meet the criteria specified in
/// OAuth 2.0 Token Revocation (RFC 7009).
/// It validates the authenticity of the client and the token involved in the request.
/// </summary>
/// <param name="logger">Provides logging capabilities to record validation outcomes and errors.</param>
/// <param name="clientAuthenticator">
/// The client request authenticator to be used in the validation process. Ensures that the client sending the
/// revocation request is authenticated and authorized to revoke tokens.
/// </param>
/// <param name="jwtValidator">
/// The JWT validator to be used for validating the token included in the revocation request. Ensures that
/// the token is valid and that it belongs to the client requesting revocation.
/// </param>
/// <param name="rateLimiter">
/// The budget of revocation requests one caller gets: a confidential client's own, and for a public client
/// one held jointly by its identifier and the address the request came from.
/// </param>
/// <param name="requestInfoProvider">
/// Names the address a request came from, which is half of what a public client's budget is charged to.
/// </param>
public partial class RevocationRequestValidator(
	ILogger<RevocationRequestValidator> logger,
	IClientAuthenticator clientAuthenticator,
	IAuthServiceJwtValidator jwtValidator,
	[FromKeyedServices(CallerRateLimiters.Revocation)]
	PartitionedRateLimiter<(string ClientId, string? Source)> rateLimiter,
	IRequestInfoProvider requestInfoProvider)
	: IRevocationRequestValidator
{
	/// <summary>
	/// Asynchronously validates a revocation request against the OAuth 2.0 revocation request specifications.
	/// It checks the client's credentials and the validity of the token to be revoked. The validation ensures
	/// that the token belongs to the authenticated client and is valid as per JWT standards.
	/// </summary>
	/// <param name="revocationRequest">
	/// The revocation request to be validated. Contains the token to be revoked and client information.
	/// </param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>
	/// A <see cref="Task"/> representing the asynchronous operation, which upon completion will yield a
	/// <see cref="Result{ValidRevocationRequest, AuthError}"/>. The result indicates whether the request is valid or
	/// contains any errors.
	/// </returns>
	/// <remarks>
	/// This method follows the OAuth 2.0 revocation flow, ensuring that the token being revoked belongs to
	/// the authenticated client, protecting against cross-client token revocation. In case of validation failure,
	/// it logs a warning with the specific cause.
	/// </remarks>
	public async Task<Result<ValidRevocationRequest, OidcError>> ValidateAsync(
		RevocationRequest revocationRequest,
		ClientRequest clientRequest)
	{
		// Authenticate the client making the revocation request. Public clients (auth method
		// "none") are deliberately allowed through: RFC 7009 section 5 states a revocation request
		// "must contain a valid client_id, in the case of a public client, or valid client
		// credentials, in the case of a confidential client", and the spec's own security
		// analysis dismisses the guessed-client_id threat - a guessed token is worth far more
		// used than revoked. The protection the spec actually mandates is the token-ownership
		// check below. Do not re-add a public-client rejection here: it slipped in once and
		// left every SPA and native client unable to revoke its own refresh token on logout.
		var clientInfo = await clientAuthenticator.TryAuthenticateClientAsync(clientRequest);
		if (clientInfo == null)
		{
			return new OidcError(
				ErrorCodes.InvalidClient,
				"The client is not authorized");
		}

		// Charged after the caller has proven which client it is and before the token is read: reading it
		// verifies a signature, which is what a looping client makes this server repeat. The budget is this
		// endpoint's own, so a client flooding introspection can still revoke a token it believes is stolen.
		if (BudgetFor(clientInfo) is not { } budgetKey)
			return await ReadTokenAsync(revocationRequest, clientInfo);

		// The lease is held until this method returns, so a host that substitutes a limiter counting requests
		// in flight bounds the token validation below rather than nothing at all.
		using var lease = rateLimiter.AttemptAcquire(budgetKey);
		if (!lease.IsAcquired)
		{
			// The refusal names the budget that was spent rather than the request that met it: a budget one
			// client holds everywhere is not the one it holds at a single address, and an operator reading
			// the second has to know which address it was before the line means anything.
			if (budgetKey.Source is { } source)
			{
				LogCallerAndSourceRateLimited(clientInfo.ClientId, source);
			}
			else
			{
				LogCallerRateLimited(clientInfo.ClientId);
			}

			return new TooManyRequestsError(
				"Too many revocation requests from this client",
				lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) ? retryAfter : null);
		}

		return await ReadTokenAsync(revocationRequest, clientInfo);
	}

	/// <summary>
	/// Names the budget this caller's request is charged to, or null when it is charged to none.
	/// </summary>
	/// <remarks>
	/// A request in a public client's name is charged to that name paired with the address it came from, so
	/// that one sender's flood cannot reach the client's other users. When the server cannot see an address,
	/// nothing is charged: the alternative is a budget in the client's name alone, which is the thing a
	/// stranger could spend to silence its logout, and an endpoint doing unbounded work is what this endpoint
	/// did before budgets existed.
	/// <para>
	/// The last arm cannot be entered while <see cref="ClientInfo.ClientType"/> derives its answer from the
	/// authentication method and has only these two to give. It would speak if that property gained a third
	/// answer, which is the change that has to decide what such a caller proved before this line can charge it.
	/// </para>
	/// </remarks>
	private (string ClientId, string? Source)? BudgetFor(ClientInfo clientInfo)
		=> clientInfo.ClientType switch
		{
			ClientType.Confidential => (clientInfo.ClientId, (string?)null),
			ClientType.Public => requestInfoProvider.SourceName() is { } source
				? (clientInfo.ClientId, (string?)source)
				: null,
			_ => throw new InvalidOperationException(
				$"Unknown {nameof(ClientType)} {clientInfo.ClientType} for client {clientInfo.ClientId}"),
		};

	/// <summary>
	/// Reads the token the request names and decides whether it belongs to the client that asked.
	/// </summary>
	private async Task<Result<ValidRevocationRequest, OidcError>> ReadTokenAsync(
		RevocationRequest revocationRequest,
		ClientInfo clientInfo)
	{
		// The audience is deliberately not required to name this server. RFC 7009 Section 2.1 has the client
		// revoke a token it holds, and what settles the request is whether the token belongs to that client -
		// the check below. A token minted for a resource indicator names that resource in its audience, and
		// demanding otherwise would leave the client unable to revoke exactly the tokens most worth revoking.
		var result = await jwtValidator.ValidateAsync(
			revocationRequest.Token,
			ValidationOptions.Default & ~ValidationOptions.RequireValidAudience);

		return result.Match(
			token =>
			{
				// If the token was issued to a different client, log a warning and return an invalid token result.
				if (token is { Payload.ClientId: {} clientId } && clientId != clientInfo.ClientId)
				{
					LogTokenIssuedToAnotherClient(clientId);
					return ValidRevocationRequest.InvalidToken(revocationRequest);
				}

				// If the token is valid and belongs to the authenticated client, return a valid revocation request.
				return new ValidRevocationRequest(revocationRequest, token);
			},
			error =>
			{
				LogTokenValidationFailed(error);
				return ValidRevocationRequest.InvalidToken(revocationRequest);
			});
	}
}
