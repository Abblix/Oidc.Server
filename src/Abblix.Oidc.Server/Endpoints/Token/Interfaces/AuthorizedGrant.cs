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
}
