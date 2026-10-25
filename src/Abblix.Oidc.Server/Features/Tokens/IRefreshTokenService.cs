// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Issues and consumes OAuth 2.0 refresh tokens (RFC 6749 section 6) used to obtain renewed access
/// tokens without re-prompting the user. Implementations apply the configured absolute and
/// sliding expiration policies and may revoke the previous refresh token when reuse is
/// disallowed.
/// </summary>
public interface IRefreshTokenService
{
	/// <summary>
	/// Issues a refresh token for the supplied authentication session and authorization context.
	/// When <paramref name="refreshToken"/> is non-null the call renews that token without spending it; the
	/// caller spends it with <see cref="TrySpendAsync"/> once the response is complete. Returns
	/// <c>null</c> when expiration policies have already elapsed and no new token can be issued.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="authSession">The authentication session the token continues.</param>
	/// <param name="authContext">The authorization context the token carries.</param>
	/// <param name="clientInfo">The client the token is issued to.</param>
	/// <param name="refreshToken">The token being rotated, or <c>null</c> for the first token of a grant.</param>
	/// <param name="grantId">The family the new token joins. The caller decides it, because the access token
	/// issued in the same response belongs to the same family and is minted first.</param>
	Task<EncodedJsonWebToken?> CreateRefreshTokenAsync(
		TenantDefinition tenant,
		AuthSession authSession,
		AuthorizationContext authContext,
		ClientInfo clientInfo,
		JsonWebToken? refreshToken,
		string grantId);

	/// <summary>
	/// Spends a refresh token that was renewed, so that a token the client's policy rotates renews once.
	/// </summary>
	/// <remarks>
	/// Called once every token of the response has been issued, so a failure on the way leaves the presented
	/// token unspent, and only when a new refresh token was issued for it. When another request has already
	/// spent the token, the grant is revoked as for any replay of a superseded token, because two presentations
	/// arriving together cannot be told from a stolen copy. A token the client's policy does not rotate is left
	/// unspent, and so is one presented for a request that issues no new refresh token, such as one narrowing its
	/// scope to leave out offline access.
	/// </remarks>
	/// <param name="tenant">The tenant the token is for.</param>
	/// <param name="refreshToken">The refresh token presented for renewal.</param>
	/// <param name="clientInfo">The client renewing it.</param>
	/// <returns>True when the request may go on; false when the token had already been spent.</returns>
	Task<bool> TrySpendAsync(TenantDefinition tenant, JsonWebToken refreshToken, ClientInfo clientInfo);

	/// <summary>
	/// Reconstructs the <see cref="AuthorizedGrant"/> represented by a previously issued refresh
	/// token, or returns an <see cref="OidcError"/> when the token cannot be honored.
	/// </summary>
	public Task<Result<AuthorizedGrant, OidcError>> AuthorizeByRefreshTokenAsync(
		TenantDefinition tenant,
		JsonWebToken refreshToken,
		ClientInfo clientInfo);
}
