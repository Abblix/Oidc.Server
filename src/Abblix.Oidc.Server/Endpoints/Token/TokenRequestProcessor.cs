// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens;


namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Default <see cref="ITokenRequestProcessor"/>: always issues an access token (RFC 6749 section 5.1),
/// adds a refresh token when <c>offline_access</c> is in the granted scope (OIDC Core 1.0 section 11),
/// and adds an ID token when <c>openid</c> is in scope (OIDC Core 1.0 section 3.1.3.3, with <c>at_hash</c>
/// computed from the issued access token).
/// </summary>
/// <param name="accessTokenService">Issues access-token JWTs.</param>
/// <param name="refreshTokenService">Issues refresh-token JWTs, rolling the previous one for refresh-token grants.</param>
/// <param name="identityTokenService">Issues ID tokens.</param>
/// <param name="tokenContextEvaluator">Narrows scopes/resources and computes mTLS confirmation binding.</param>
public class TokenRequestProcessor(
	IAccessTokenService accessTokenService,
	IRefreshTokenService refreshTokenService,
	IIdentityTokenService identityTokenService,
	ITokenAuthorizationContextEvaluator tokenContextEvaluator) : ITokenRequestProcessor
{
	/// <summary>
	/// Asynchronously processes a valid token request, determining the necessary tokens to generate based on
	/// the request's scope and grant type. It generates an access token for every request and, depending on the scope,
	/// may also generate a refresh token and an ID token for OpenID Connect authentication.
	/// </summary>
	/// <param name="request">The validated token request containing client and authorization session information.
	/// </param>
	/// <returns>A task representing the asynchronous operation, yielding a <see cref="TokenIssued"/> containing
	/// the generated tokens, or an <see cref="OidcError"/> if processing fails.</returns>
	/// <remarks>
	/// Access tokens authorize clients for resource access; refresh tokens enable long-lived sessions by allowing
	/// new access tokens to be obtained without re-authentication; ID tokens provide identity information about
	/// the user, crucial for OpenID Connect authentication flows. This method ensures secure and compliant token
	/// generation.
	/// </remarks>
	public async Task<Result<TokenIssued, OidcError>> ProcessAsync(ValidTokenRequest request)
	{
		var clientInfo = request.ClientInfo;
		clientInfo.CheckClientLicense();

		var authContext = tokenContextEvaluator.EvaluateAuthorizationContext(request);

		// RFC 6749 section 5.2/section 6 and RFC 8707 section 2.2: a token request may only narrow what the grant carries,
		// never reach for scopes or resources it never held. The evaluator intersects requested with
		// granted; a non-empty request that collapses to an empty intersection means the client asked
		// for scopes/resources the grant does not cover. Issuing a scopeless token, or one whose audience
		// silently falls back to the client id, would hand back different authority than was asked for.
		if (request.Scope is { Length: > 0 } && authContext.Scope is not { Length: > 0 })
		{
			return new OidcError(
				ErrorCodes.InvalidScope,
				"The requested scope exceeds the scope granted by the resource owner.");
		}

		if (request.Resources is { Length: > 0 }
			&& request.AuthorizedGrant.Context.Resources is { Length: > 0 }
			&& authContext.Resources is not { Length: > 0 })
		{
			return new OidcError(
				ErrorCodes.InvalidTarget,
				"The requested resource is not among the resources granted by the resource owner.");
		}

		var accessToken = await accessTokenService.CreateAccessTokenAsync(
			request.AuthorizedGrant.AuthSession,
			authContext,
			clientInfo);

		// RFC 9449 section 7.1: a DPoP-bound access token (cnf.jkt populated by the evaluator
		// from the proof key) advertises token_type "DPoP"; otherwise "Bearer".
		var tokenType = !string.IsNullOrEmpty(authContext.ProofKeyThumbprint)
			? TokenTypes.DPoP
			: TokenTypes.Bearer;

		var response = new TokenIssued(
			accessToken,
			tokenType,
			clientInfo.AccessTokenExpiresIn,
			TokenTypeIdentifiers.AccessToken)
		{
			// RFC 9396 section 7: the AS MUST return the authorization_details "as granted by the resource owner
			// and assigned to the respective access token", and the same section lets the server OMIT
			// values while never letting it name more than the token holds.
			//
			// Read out of the token that was just minted rather than out of the context it was minted
			// from. The two diverge whenever FilterAuthorizationDetailsByLocation is on: the token carries
			// the entries this audience may read, so a response built from the context would advertise the
			// ones that were dropped. A client told that would send the token to a location its own claim
			// does not name, and the refusal would come back from the resource server looking like a bad
			// token.
			//
			// Copied rather than handed over, because the array is parented inside the token's payload:
			// a host attaching the response's array to its own object would parent the same node twice
			// and the second serialise would throw, and anything editing it would be editing the claim
			// inside the issued token.
			AuthorizationDetails =
				accessToken.Token.Payload.Json[IanaClaimTypes.AuthorizationDetails] is JsonArray issued
					? (JsonArray)issued.DeepClone()
					: null,
		};

		// RFC 6749 section 4.4.3 forbids a refresh token for client_credentials, and an RFC 8693 token exchange
		// returns neither a refresh token nor an ID token - the exchanged access token is the whole
		// deliverable. Gate both derived-token branches by grant type so a stray offline_access or openid
		// scope (inherited from a subject_token, or placed by the host in the client's AllowedScopes)
		// cannot mint a credential these grants must never produce. All user-facing grants
		// (authorization_code, refresh_token, password, CIBA, device_code, jwt-bearer) fall through unchanged.
		var grantType = request.Model.GrantType;
		var mayIssueDerivedTokens =
			grantType != GrantTypes.ClientCredentials &&
			grantType != GrantTypes.TokenExchange;

		if (mayIssueDerivedTokens && authContext.Scope.HasFlag(Scopes.OfflineAccess))
		{
			var refreshContext = request.AuthorizedGrant.Context with
			{
				// RFC 9449 section 5 confidential-vs-public split:
				ProofKeyThumbprint = clientInfo.ClientType switch
				{
					//   * Confidential clients: refresh tokens are not separately DPoP-bound,
					//     client authentication already sender-constrains them. Stripping the
					//     committed jkt from the persisted refresh-token context lets a follow-up
					//     refresh call skip the committed-vs-presented compare in
					//     DPoPTokenEndpointValidator, allowing key rotation per section 5's carve-out.
					ClientType.Confidential => null,

					//   * Public clients: DPoP is the SOLE sender-constraint, so section 5 mandates
					//     same-key MUST on every refresh. Source the binding from authContext
					//     (the evaluator stamps the live proof's thumbprint) rather than from
					//     the original grant context, otherwise a non-PAR initial flow loses
					//     the binding and the next refresh would accept any key - a section 5 violation.
					//     authContext.ProofKeyThumbprint is null when the request carried no proof,
					//     which keeps Bearer-only public flows unchanged.
					_ => authContext.ProofKeyThumbprint,
				},
			};

			response.RefreshToken = await refreshTokenService.CreateRefreshTokenAsync(
				request.AuthorizedGrant.AuthSession,
				refreshContext,
				clientInfo,
				request.AuthorizedGrant is RefreshTokenAuthorizedGrant { RefreshToken: var refreshToken }
					? refreshToken
					: null);
		}

		if (mayIssueDerivedTokens && authContext.Scope.HasFlag(Scopes.OpenId))
		{
			// The bindings exist only when the caller says it IS the push path. The mode could be read
			// off clientInfo instead, and is not, so that this method does not have to know CIBA's
			// delivery rules to serve every other grant type - see PushDeliveryBindings.
			//
			// The refresh token is read from the RESPONSE because it was minted above. That order is
			// load-bearing: assembling these bindings before the branch that mints it silently drops
			// rt_hash from every push notification that carries one.
			var pushBindings = request.PushDeliveryOf is { } authenticationRequestId
				? new PushDeliveryBindings(authenticationRequestId, response.RefreshToken?.EncodedJwt)
				: null;

			response.IdToken = await identityTokenService.CreateIdentityTokenAsync(
				request.AuthorizedGrant.AuthSession,
				authContext,
				clientInfo,
				false,
				null,
				accessToken.EncodedJwt,
				pushBindings);
		}

		return response;
	}
}
