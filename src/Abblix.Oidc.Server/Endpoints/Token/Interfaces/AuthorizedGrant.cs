// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.UserAuthentication;


namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// The (authentication-session, authorization-context) pair from which the token endpoint mints
/// access, refresh and ID tokens. Produced by an <see cref="Grants.IAuthorizationGrantHandler"/> and
/// carried through token issuance.
/// </summary>
/// <param name="AuthSession">The user's authentication session (subject, sid, auth_time, idp).</param>
/// <param name="Context">The authorization decision (client_id, scope, resources, requested claims,
/// confirmation binding) inherited by the issued tokens.</param>
public record AuthorizedGrant(AuthSession AuthSession, AuthorizationContext Context)
{
    /// <summary>
    /// Tokens already issued from this grant. Tracked for the authorization-code reuse defense:
    /// if the same code is presented twice, every previously issued token is revoked by JTI.
    /// </summary>
    public TokenInfo[]? IssuedTokens { get; init; }

    /// <summary>
    /// The refresh token family whose authority this grant exercises, so the tokens minted from it join that
    /// family and a revoked family refuses them (RFC 9700 section 4.14.2). Set by a grant handler that inherits
    /// one without holding the token that states it, as a token exchange does from its subject token; a
    /// <see cref="RefreshTokenAuthorizedGrant"/> states it in the token it carries instead, so it does not
    /// repeat it here. <c>null</c> where the grant exercises no such authority, in which case a grant issuing its
    /// first refresh token starts a family of its own.
    /// </summary>
    public string? GrantId { get; init; }
}
