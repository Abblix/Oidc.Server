// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
	/// When <paramref name="refreshToken"/> is non-null the call represents a refresh-token
	/// rotation and the previous token may be revoked according to the client's policy. Returns
	/// <c>null</c> when expiration policies have already elapsed and no new token can be issued.
	/// </summary>
	Task<EncodedJsonWebToken?> CreateRefreshTokenAsync(
		AuthSession authSession,
		AuthorizationContext authContext,
		ClientInfo clientInfo,
		JsonWebToken? refreshToken);

	/// <summary>
	/// Reconstructs the <see cref="AuthorizedGrant"/> represented by a previously issued refresh
	/// token, or returns an <see cref="OidcError"/> when the token cannot be honored.
	/// </summary>
	public Task<Result<AuthorizedGrant, OidcError>> AuthorizeByRefreshTokenAsync(
		JsonWebToken refreshToken,
		ClientInfo clientInfo);
}
