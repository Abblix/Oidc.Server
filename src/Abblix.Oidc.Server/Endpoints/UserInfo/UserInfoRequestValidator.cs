// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using static Abblix.Oidc.Server.Model.UserInfoRequest;
using Abblix.Oidc.Server.Features.MultiTenancy;



namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// Validates a UserInfo request: extracts the access token (per RFC 6750, either the
/// <c>Authorization: Bearer</c> header or the <c>access_token</c> form or query parameter, exactly one of them),
/// verifies its JWT signature and claims, asserts the <c>typ</c> header equals <c>at+jwt</c>, and
/// resolves the originating authentication session, authorization context and client.
/// </summary>
/// <param name="jwtValidator">Validates access-token JWTs issued by this authorization server.</param>
/// <param name="accessTokenService">Resolves an <see cref="Abblix.Oidc.Server.Features.UserAuthentication.AuthSession"/> and
/// <see cref="AuthorizationContext"/> from the access token.</param>
/// <param name="clientInfoProvider">Loads the <see cref="ClientInfo"/> for the token's client.</param>
/// <param name="dpopValidator">RFC 9449 section 7 DPoP resource-server-side validator that enforces the
/// proof-of-possession binding when the access token carries a <c>cnf.jkt</c> confirmation.</param>
/// <param name="mtlsValidator">RFC 8705 section 3 mutual-TLS resource-server-side validator that enforces
/// the certificate binding when the access token carries a <c>cnf.x5t#S256</c> confirmation.</param>
public class UserInfoRequestValidator(
	IAuthServiceJwtValidator jwtValidator,
	IAccessTokenService accessTokenService,
	IClientInfoProvider clientInfoProvider,
	IDPoPUserInfoValidator dpopValidator,
	IMtlsUserInfoValidator mtlsValidator) : IUserInfoRequestValidator
{
	/// <summary>
	/// Asynchronously validates a user information request and determines its validity based on
	/// the provided access token and request parameters.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="userInfoRequest">The user info request to validate.</param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>A <see cref="Task"/> representing the asynchronous operation,
	/// which upon completion will yield a <see cref="Result{ValidUserInfoRequest, AuthError}"/>.</returns>
	public async Task<Result<ValidUserInfoRequest, OidcError>> ValidateAsync(
		TenantDefinition tenant,
		UserInfoRequest userInfoRequest,
		ClientRequest clientRequest)
	{
		var tokenResult = ExtractAccessToken(userInfoRequest, clientRequest);
		if (tokenResult.TryGetFailure(out var tokenError))
			return tokenError;

		var jwtAccessToken = tokenResult.GetSuccess();

		// RFC 9068 Section 2.2 lists exp among the REQUIRED claims of a JWT access token, and
		// Section 4 makes the consequence explicit: "The current time MUST be before the time
		// represented by the exp claim." An access token without one would otherwise never expire.
		//
		// The audience is validated here because this endpoint is a protected resource
		// (OpenID Connect Core 1.0 Section 1.2), so Section 4 binds it: "The resource server MUST validate
		// that the aud claim contains a resource indicator value corresponding to an identifier the resource
		// server expects for itself." The identifier this endpoint expects for itself is the issuer, which is
		// what an access token carries when its request named no resource. Section 5 is why the check matters
		// rather than being a formality: distinct audiences per resource exist to prevent cross-JWT confusion,
		// and accepting a token minted for someone else's API here is that confusion.
		//
		// RFC 9068 Section 4: "The resource server MUST verify that the 'typ' header value is 'at+jwt' or
		// 'application/at+jwt' and reject tokens carrying any other value."
		//
		// No client presents a bearer token, so the validator holds it to the profile of the client it names (FAPI 2.0
		// section 5.4.1, "when creating or processing JWTs"), each JWE layer included.
		var result = await jwtValidator.ValidateAsync(
			tenant, jwtAccessToken,
			TokenTypePolicy.Exactly(JsonWebTokenTypes.AccessToken),
			ValidationOptions.Default | ValidationOptions.RequireExpirationTime);

		if (result.TryGetFailure(out var error))
			return new OidcError(ErrorCodes.InvalidToken, error.ToString());

		var token = result.GetSuccess();

		// The client is named by the token, so it is known only once the token is trusted, and it is resolved here,
		// before the proof: the lookup only reads, while the proof check spends the proof's jti. A pairwise access
		// token's 'sub' is also opened back to the real subject with the client's sector further down.
		var clientId = token.Payload.ClientId;
		var clientInfo = clientId is not null
			? await clientInfoProvider.TryFindClientAsync(tenant, clientId)
			: null;

		if (clientInfo == null)
		{
			return new OidcError(
				ErrorCodes.InvalidToken,
				$"The client '{clientId}' is not found");
		}

		// RFC 9449 section 7.1 RS-side enforcement: when the access token carries cnf.jkt the
		// request MUST present it via the DPoP scheme together with a valid DPoP proof
		// whose key thumbprint matches cnf.jkt and whose ath claim matches the access
		// token. Runs before AuthenticateByAccessTokenAsync so a bad-DPoP token never
		// surfaces auth-session probes downstream. The proof is judged under the client's profile, as the token is.
		var dpopError = await dpopValidator.ValidateAsync(tenant, clientInfo, clientRequest, token, jwtAccessToken);
		if (dpopError is not null)
			return dpopError;

		// RFC 8705 section 3 RS-side enforcement: when the access token carries cnf.x5t#S256 the
		// certificate presented on the mutual-TLS connection MUST hash to the bound value.
		// Independent of the DPoP binding above - a token carrying both must satisfy each.
		var mtlsError = mtlsValidator.Validate(clientRequest, token);
		if (mtlsError is not null)
			return mtlsError;

		// FAPI 2.0 Security Profile section 5.3.4 and FAPI 1.0 Part 1 section 6.2.1: a resource server "shall not accept
		// access tokens in the query parameters". Which profile holds the client is known only from the validated token, so the refusal comes
		// here, still before the token opens the user's session. Extraction admits exactly one source, so a token in
		// the query is the token that was validated.
		if (userInfoRequest.AccessTokenInQuery != null &&
		    SecurityProfileRequirements.For(clientInfo, tenant.DefaultSecurityProfile).RequireAccessTokenOutsideQuery)
		{
			return new OidcError(
				ErrorCodes.InvalidRequest,
				$"The access token must be passed via '{HttpRequestHeaders.Authorization}' header or the request body, " +
				$"the '{Parameters.AccessToken}' query parameter is not accepted under the client's security profile");
		}

		// A pairwise subject that does not open for this client (a foreign-sector or pre-change token) comes back as
		// an error rather than faulting, so it surfaces as a normal invalid_token rejection.
		return (await accessTokenService.AuthenticateByAccessTokenAsync(tenant, token, clientInfo))
			.Bind(grant => Authorize(userInfoRequest, grant, clientInfo));
	}

	/// <summary>
	/// Admits the grant the token opened to the UserInfo Endpoint, or says why its authorization falls short.
	/// </summary>
	/// <remarks>
	/// OpenID Connect Core 1.0 section 5.3: the endpoint is called "using an Access Token obtained through OpenID
	/// Connect Authentication", which carries the openid scope. FAPI 2.0 Security Profile section 5.3.4 has the
	/// resource server verify the authorization "is sufficient for the requested resource access and otherwise return
	/// errors as in Section 3.1" of RFC 6750, which names that insufficient_scope.
	/// </remarks>
	private static Result<ValidUserInfoRequest, OidcError> Authorize(
		UserInfoRequest userInfoRequest,
		AuthorizedGrant grant,
		ClientInfo clientInfo)
	{
		if (!grant.Context.Scope.Contains(Scopes.OpenId, StringComparer.Ordinal))
		{
			return new OidcError(
				ErrorCodes.InsufficientScope,
				$"The access token was not granted the '{Scopes.OpenId}' scope");
		}

		return new ValidUserInfoRequest(userInfoRequest, grant.AuthSession, grant.Context, clientInfo);
	}

	/// <summary>
	/// Extracts the access token from exactly one source per RFC 6750 section 2: the <c>Authorization</c> header (Bearer or
	/// DPoP scheme), the <c>access_token</c> parameter in the body, or the same parameter in the query, never two of
	/// them. Returns the typed
	/// <see cref="MissingAuthenticationError"/> when neither is present so the challenge builder omits error
	/// attributes.
	/// </summary>
	private static Result<string, OidcError> ExtractAccessToken(
		UserInfoRequest userInfoRequest,
		ClientRequest clientRequest)
	{
		// RFC 6750 section 3.1 names a request that "uses more than one method for including an access token" an
		// invalid_request. The query and the body are told apart only so a profile can refuse one of them
		if (userInfoRequest is { AccessTokenInForm: not null, AccessTokenInQuery: not null })
			return new OidcError(
				ErrorCodes.InvalidRequest,
				$"The '{Parameters.AccessToken}' parameter must be passed in the request body or the query, " +
				"but not in both at the same time");

		var parameter = userInfoRequest.AccessToken;
		var authorizationHeader = clientRequest.AuthorizationHeader;
		if (authorizationHeader == null)
		{
			if (parameter != null)
				return parameter;

			// RFC 6750 section 3.1: a request with no authentication information at all gets a bare WWW-Authenticate
			// challenge - the typed marker tells the challenge builder to omit the error attributes.
			return new MissingAuthenticationError(
				$"The access token must be passed via '{HttpRequestHeaders.Authorization}' header " +
				$"or '{Parameters.AccessToken}' parameter, but none of them specified");
		}

		// RFC 6750 section 3.1: the header and a parameter together are "more than one method for including an access
		// token", an invalid_request like the body and the query together above. Decided before the scheme, since a
		// request carrying a token does not lack authentication information whatever its header names
		if (parameter != null)
			return new OidcError(
				ErrorCodes.InvalidRequest,
				$"The access token must be passed via '{HttpRequestHeaders.Authorization}' header " +
				$"or '{Parameters.AccessToken}' parameter, but not in both sources at the same time");

		// RFC 9449 section 7.1: DPoP-bound access tokens are presented via the DPoP scheme. The actual scheme/binding
		// compatibility check runs after JWT parse so we can inspect cnf.jkt - here we only reject unknown schemes.
		// RFC 6750 section 3.1: a request "attempted using an unsupported authentication method" lacks authentication
		// information, and the resource server "SHOULD NOT include an error code or other error information"
		if (!authorizationHeader.HasScheme(TokenTypes.Bearer) && !authorizationHeader.HasScheme(TokenTypes.DPoP))
			return new MissingAuthenticationError(
				$"The scheme name '{authorizationHeader.Scheme}' is not supported");

		// RFC 6750 section 2.1: the credentials are "Bearer" 1*SP b64token, so the scheme alone is a malformed request,
		// which section 3.1 names invalid_request, rather than a token found invalid
		if (authorizationHeader.Parameter == null)
			return new OidcError(
				ErrorCodes.InvalidRequest,
				$"The access token must be specified via '{HttpRequestHeaders.Authorization}' header");

		return authorizationHeader.Parameter;
	}
}
