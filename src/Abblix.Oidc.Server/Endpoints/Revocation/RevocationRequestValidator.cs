// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
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
public partial class RevocationRequestValidator(
	ILogger<RevocationRequestValidator> logger,
	IClientAuthenticator clientAuthenticator,
	IAuthServiceJwtValidator jwtValidator) : IRevocationRequestValidator
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
