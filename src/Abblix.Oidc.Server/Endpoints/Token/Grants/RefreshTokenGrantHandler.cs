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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// <see cref="IAuthorizationGrantHandler"/> for <c>grant_type=refresh_token</c> (RFC 6749 section 6).
/// Verifies the refresh token's signature and lifetime, requires the JWT <c>typ</c> header to be
/// <c>rt+jwt</c>, recovers the original <see cref="AuthorizedGrant"/>, and rejects the request with
/// <c>invalid_grant</c> when the refreshing client differs from the client that received the token.
/// </summary>
/// <param name="jwtValidator">Reads the refresh token: first that it is authentic, then, once it is found to belong
/// to the client presenting it, what is recorded about it.</param>
/// <param name="refreshTokenService">Resolves the refresh-token JWT to an <see cref="AuthorizedGrant"/>
/// and enforces single-use / rotation semantics.</param>
public class RefreshTokenGrantHandler(
	IAuthServiceJwtReader jwtValidator,
	IRefreshTokenService refreshTokenService) : IAuthorizationGrantHandler
{
	/// <summary>
	/// Indicates that this handler is responsible for processing the 'refresh_token' grant type.
	/// The framework uses this information to ensure that this handler is only invoked for the refresh token flow.
	/// </summary>
	public IEnumerable<string> GrantTypesSupported
	{
		get { yield return GrantTypes.RefreshToken; }
	}

	/// <summary>
	/// Processes a token request using the refresh token grant type.
	/// This method validates the refresh token, ensures that the token is associated with the correct client,
	/// and generates new tokens if the request is valid.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="request">The token request, containing the refresh token and other required parameters.</param>
	/// <param name="clientInfo">
	/// The client information, used to verify the request is coming from an authorized client.</param>
	/// <returns>
	/// A task representing the outcome of the authorization process, either returning a successful grant with a new
	/// access token or an error if the request is invalid or the refresh token is unauthorized.
	/// </returns>
	/// <param name="clients">The clients of the request being served, where a client a presented token names
	/// is looked up.</param>
	/// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
	public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TenantDefinition tenant, TokenRequest request, ClientInfo clientInfo, IClientInfoProvider clients, CancellationToken cancellationToken)
	{
		// RFC 6749 section 5.2: a missing required parameter is the caller's protocol error (invalid_request),
		// not a server fault - the previous throw-on-access surfaced it as HTTP 500.
		if (!request.RefreshToken.HasValue())
		{
			return ErrorFactory.MissingParameter(TokenRequest.Parameters.RefreshToken);
		}

		// A refresh token issued by 3.0 holds the resources of the grant it continues in its audience
		// (RefreshTokenResources), so the audience need not name this server.
		var authentic = await jwtValidator.ReadAuthenticAsync(
			tenant,
			clientInfo,
			clients,
			request.RefreshToken,
			TokenTypePolicy.Exactly(JwtTypes.RefreshToken),
			ServiceTokenValidation.AnyAudience);

		if (authentic.TryGetFailure(out var error))
		{
			return new OidcError(ErrorCodes.InvalidGrant, error.ErrorDescription);
		}

		// RFC 6749 section 6: the server MUST "ensure that the refresh token was issued to the authenticated client".
		// Decided before the token's records are read, because reading them revokes the grant of a superseded refresh
		// token, which a client holding another client's token would otherwise do to it from here, and they are judged by
		// the token's own client, whose answer decides nothing for a token that is not the caller's
		var presented = authentic.GetSuccess();
		if (!presented.BelongsTo(clientInfo.ClientId))
		{
			return new OidcError(
				ErrorCodes.InvalidGrant,
				"The specified grant belongs to another client");
		}

		var recorded = await jwtValidator.ReadRecordsAsync(tenant, clients, presented, ServiceTokenValidation.AnyAudience);
		if (recorded.TryGetFailure(out error))
		{
			return new OidcError(ErrorCodes.InvalidGrant, error.ErrorDescription);
		}

		// The authenticated client is the one the refresh token was issued to, so its sector opens a pairwise subject
		// back to the real subject.
		var result = await refreshTokenService.AuthorizeByRefreshTokenAsync(tenant, recorded.GetSuccess(), clientInfo);
		if (result.TryGetFailure(out var authError))
		{
			return authError;
		}

		var grant = result.GetSuccess();

		// A refresh token exists only for offline access, so withdrawing the permission ends the ones already issued;
		// renewing without a new refresh token would leave the presented one unspent and reusable until it expires
		if (!clientInfo.OfflineAccess.IsAllowed())
		{
			return new OidcError(
				ErrorCodes.InvalidGrant,
				"This client is not allowed offline access");
		}

		// If everything is valid, return the authorized result.
		return grant;
	}
}
