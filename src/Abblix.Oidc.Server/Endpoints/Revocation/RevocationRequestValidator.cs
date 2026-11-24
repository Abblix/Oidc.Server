// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.RateLimiting;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Validation;
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
/// Reads the token the request names: first that it is authentic, then, once it is found to belong to the client
/// asking, what is recorded about it.
/// </param>
/// <param name="rateLimiter">
/// The budget of revocation requests one caller gets: a confidential client's own, and for a public client
/// one held jointly by its identifier and the address the request came from.
/// </param>
/// <param name="requestInfoProvider">
/// Names the address a request came from, which is half of what a public client's budget is charged to.
/// </param>
/// <param name="unnamedSource">Says, once, that a public client's request arrived from no address and so
/// went uncharged.</param>
/// <param name="clientInfoProvider">The client store, asked through a lookup made for each request.</param>
public partial class RevocationRequestValidator(
	ILogger<RevocationRequestValidator> logger,
	IClientAuthenticator clientAuthenticator,
	IClientInfoProvider clientInfoProvider,
	IAuthServiceJwtReader jwtValidator,
	[FromKeyedServices(CallerRateLimiters.Revocation)]
	PartitionedRateLimiter<(string ClientId, string? Source)> rateLimiter,
	IRequestInfoProvider requestInfoProvider,
	UnnamedSourceNotice unnamedSource)
	: IRevocationRequestValidator
{
	/// <summary>
	/// Asynchronously validates a revocation request against the OAuth 2.0 revocation request specifications.
	/// It checks the client's credentials and the validity of the token to be revoked. The validation ensures
	/// that the token belongs to the authenticated client and is valid as per JWT standards.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
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
		TenantDefinition tenant,
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
		//
		// RFC 7009 section 2.2.1 presents errors as RFC 6749 section 5.2 does, which names a request that "includes
		// multiple credentials, utilizes more than one mechanism for authenticating the client" an invalid_request.
		// Decided before the authenticator, which would count a failed attempt
		if (clientRequest.HasMoreThanOneAuthorizationHeader)
			return ErrorFactory.MoreThanOneAuthorizationHeader;

		// One lookup of the clients for the whole request: the client authentication and the reading of the token find
		// each client once. Only a failed authentication is answered as meeting a client that cannot be had for now: a
		// token of the caller finds the answer the authentication received, and reading a token of another client may
		// look that client up too, to hold the token to its profile, but such a token is answered alike whatever its
		// client's document says
		var clients = new RequestScopedClientInfoProvider(clientInfoProvider);
		var authenticated = await clientAuthenticator.TryAuthenticateClientAsync(tenant, clientRequest, clients);
		if (!authenticated.TryGetSuccess(out var clientInfo))
		{
			// RFC 6749 section 5.2 names a request that "utilizes more than one mechanism for authenticating the
			// client" an invalid_request, not a failed authentication
			if (authenticated.GetFailure() is MoreThanOneClientAuthenticationMethodError moreThanOneMethod)
				return moreThanOneMethod;

			// RFC 7009 section 2.2.1: "If the server responds with HTTP status code 503, the client must assume the
			// token still exists and may retry after a reasonable delay", which is what a client is told whose
			// document could not be had for now (draft-ietf-oauth-client-id-metadata-document-03 section 6.1)
			return clients.RefusalOf(BasicChallenge.InvalidClient(clientRequest, "The client is not authorized"));
		}

		// Charged after the caller has proven which client it is and before the token is read: reading it
		// verifies a signature, which is what a looping client makes this server repeat. The budget is this
		// endpoint's own, so a client flooding introspection can still revoke a token it believes is stolen.
		if (RevocationBudget.KeyFor(clientInfo, requestInfoProvider, unnamedSource) is not { } budgetKey)
			return await ReadTokenAsync(tenant, clients, revocationRequest, clientInfo);

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

			return RevocationBudget.Spent(lease);
		}

		return await ReadTokenAsync(tenant, clients, revocationRequest, clientInfo);
	}

	/// <summary>
	/// Reads the token the request names and decides whether it belongs to the client that asked.
	/// </summary>
	private async Task<Result<ValidRevocationRequest, OidcError>> ReadTokenAsync(
		TenantDefinition tenant,
		IClientInfoProvider clients,
		RevocationRequest revocationRequest,
		ClientInfo clientInfo)
	{
		// The audience is deliberately not required to name this server. RFC 7009 Section 2.1 has the client
		// revoke a token it holds, and what settles the request is whether the token belongs to that client -
		// the check below. A token minted for a resource indicator names that resource in its audience, and
		// demanding otherwise would leave the client unable to revoke exactly the tokens most worth revoking.
		var authentic = await jwtValidator.ReadAuthenticAsync(
			tenant,
			clientInfo,
			clients,
			revocationRequest.Token,
			JwtTypes.IntrospectableTokens,
			ServiceTokenValidation.AnyAudience);

		if (!authentic.TryGetSuccess(out var token))
			return Refused(revocationRequest, authentic.GetFailure());

		// RFC 7009 Section 2.1: the server "verifies whether the token was issued to the client making the revocation
		// request". Decided before the token's records are read, because reading them is not free of effect: a
		// superseded refresh token found there revokes its whole grant, and a client holding another client's token
		// would otherwise end that client's grant by presenting it here. Section 2.1 has such a request refused; it is
		// answered here as Section 2.2 answers an invalid token, with 200 and nothing revoked, which tells the caller
		// nothing about a token that is not its own.
		if (!token.BelongsTo(clientInfo.ClientId))
		{
			if (token.OwnerOf() is { } owner)
			{
				LogTokenIssuedToAnotherClient(owner);
			}
			else
			{
				LogTokenOfNoClient(clientInfo.ClientId);
			}

			return ValidRevocationRequest.InvalidToken(revocationRequest);
		}

		var recorded = await jwtValidator.ReadRecordsAsync(tenant, clients, token, ServiceTokenValidation.AnyAudience);
		if (!recorded.TryGetSuccess(out var valid))
			return Refused(revocationRequest, recorded.GetFailure());

		return new ValidRevocationRequest(revocationRequest, valid, clientInfo);
	}

	/// <summary>
	/// The answer to a request naming a token that was not read: the request is served as one naming an invalid token,
	/// which RFC 7009 Section 2.2 answers with success.
	/// </summary>
	private ValidRevocationRequest Refused(RevocationRequest revocationRequest, JwtValidationError error)
	{
		LogRefusal(error);
		return ValidRevocationRequest.InvalidToken(revocationRequest);
	}

	/// <summary>
	/// Records why the token was not read, at the level its reason calls for.
	/// </summary>
	/// <remarks>
	/// A token a revocation already reached is the ordinary end of a sign-out: ending the session revokes its
	/// tokens, and the client then revokes its refresh token here as RFC 7009 asks. Every other refusal is a warning:
	/// a token that does not parse, verify or carry the expected type and header, one whose claims or lifetime this
	/// server does not accept, or a superseded refresh token, whose replay is what revokes a grant.
	/// </remarks>
	private void LogRefusal(JwtValidationError error)
	{
		switch (error.Error)
		{
			case JwtError.TokenRevoked:
				LogTokenAlreadyRevoked(Sanitized.Value(error));
				break;

			case JwtError.InvalidToken
				or JwtError.TokenAlreadyUsed
				or JwtError.MalformedToken
				or JwtError.InvalidAlgorithm
				or JwtError.InvalidTokenType
				or JwtError.InvalidHeader
				or JwtError.InvalidSignature:
				LogTokenValidationFailed(Sanitized.Value(error));
				break;

			default:
				throw new ArgumentOutOfRangeException(nameof(error), error.Error, "A token refusal without a log level.");
		}
	}
}
