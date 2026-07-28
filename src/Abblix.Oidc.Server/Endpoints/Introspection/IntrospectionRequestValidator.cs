// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Jwt;
using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;


namespace Abblix.Oidc.Server.Endpoints.Introspection;

/// <summary>
/// Validates the introspection request properties and authenticates a client that initiated the request.
/// </summary>
/// <remarks>
/// This class performs validation of introspection requests and client authentication.
/// It ensures that the request is authorized and the provided token is valid for the client.
/// The validation process includes checking the authenticity of the client and the integrity of the token.
/// It leverages a client request authenticator for client authentication and a JWT validator for token validation.
/// </remarks>
/// <param name="logger">The logger for logging activities within the validator.</param>
/// <param name="clientAuthenticator">The client request authenticator to authenticate the client.</param>
/// <param name="jwtValidator">The JWT validator to validate the token.</param>
public partial class IntrospectionRequestValidator(
	ILogger<IntrospectionRequestValidator> logger,
	IClientAuthenticator clientAuthenticator,
	IAuthServiceJwtValidator jwtValidator) : IIntrospectionRequestValidator
{
	/// <summary>
	/// Validates the introspection request properties and authenticates a client that initiated the request.
	/// </summary>
	/// <param name="introspectionRequest">The introspection request to validate. It includes the token and client information for validation.</param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>
	/// A task representing the asynchronous validation operation. The task result contains the
	/// <see cref="Result{ValidIntrospectionRequest, AuthError}"/> which indicates whether the request is valid or contains errors.
	/// </returns>
	public async Task<Result<ValidIntrospectionRequest, OidcError>> ValidateAsync(
		IntrospectionRequest introspectionRequest,
		ClientRequest clientRequest)
	{
		var clientInfo = await clientAuthenticator.TryAuthenticateClientAsync(clientRequest);
		if (clientInfo == null)
		{
			return new OidcError(ErrorCodes.InvalidClient, "The client is not authorized");
		}

		// RFC 7662 §2.1: the introspection endpoint MUST require some form of authorization to
		// prevent token scanning. A public client (auth method "none") presents only its client_id,
		// which is not a credential - reject it even though "none" is valid at the token endpoint.
		if (clientInfo.TokenEndpointAuthMethod == ClientAuthenticationMethods.None)
		{
			LogPublicClientRejected(clientInfo.ClientId);
			return new OidcError(ErrorCodes.InvalidClient, "The client is not authorized");
		}

		// The audience is deliberately not required to name this server. Introspection reports on a token, it
		// does not consume one, so RFC 9068 Section 4, which binds the resource server that reads a token, does
		// not apply here. Requiring it would report every token minted for a resource indicator as inactive,
		// telling the caller a token it holds was never issued.
		//
		// RFC 7662 Section 4 lists what the authorization server must check instead - expiry, not-before,
		// revocation, signature - and adds a conditional fifth: "If the token can be used only at certain
		// resource servers, the authorization server MUST determine whether or not the token can be used at
		// the resource server making the introspection call." Answering that needs the caller's identity as a
		// resource server, which the endpoint has no way to learn: it authenticates a client, and Section 4
		// notes that a piece of software acting as both "MAY reuse the same credentials", so a client
		// identifier does not say which resource is asking. The same section closes the list with "it is up to
		// the authorization server to determine which of these checks (and any other checks) apply".
		var result = await jwtValidator.ValidateAsync(
			introspectionRequest.Token,
			ValidationOptions.Default & ~ValidationOptions.RequireValidAudience);

		return result.Match(
			token =>
			{
				if (token is { Payload.ClientId: {} clientId } &&
				    clientId != clientInfo.ClientId &&
				    !clientInfo.AllowCrossClientIntrospection)
				{
					// The token was issued to another client and this caller is not authorized to act as a
					// protected resource. RFC 7662 Section 4 asks for exactly that authorization - "SHOULD
					// require protected resources to be specifically authorized to call the introspection
					// endpoint" - and says nothing about who the token belongs to, so ownership is what stands
					// in for the permission on a client that was never granted it.
					return ValidIntrospectionRequest.InvalidToken(introspectionRequest, clientInfo);
				}

				return new ValidIntrospectionRequest(introspectionRequest, clientInfo, token);

			},
			error =>
			{
				LogInvalidJwt(error);
				return ValidIntrospectionRequest.InvalidToken(introspectionRequest, clientInfo);
			});
	}
}
