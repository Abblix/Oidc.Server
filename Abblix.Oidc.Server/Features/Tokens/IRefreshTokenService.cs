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

using Abblix.Utils;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Issues and consumes OAuth 2.0 refresh tokens (RFC 6749 §6) used to obtain renewed access
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
	public Task<Result<AuthorizedGrant, OidcError>> AuthorizeByRefreshTokenAsync(JsonWebToken refreshToken);
}
