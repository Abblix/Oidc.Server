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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.UserAuthentication;


namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Represents the result of an authorized grant operation, including authentication session and authorization context.
/// </summary>
/// <param name="AuthSession">The authentication session associated with the grant.</param>
/// <param name="Context">The context of the authorization process.</param>
public record AuthorizedGrantResult(AuthSession AuthSession, AuthorizationContext Context)
    : GrantAuthorizationResult
{
    /// <summary>
    /// The optional refresh token issued during the grant authorization.
    /// </summary>
    public JsonWebToken? RefreshToken { get; set; }

    /// <summary>
    /// The list of tokens issued as a result of the grant authorization.
    /// </summary>
    public List<TokenInfo> IssuedTokens { get; set; } = new();
}
