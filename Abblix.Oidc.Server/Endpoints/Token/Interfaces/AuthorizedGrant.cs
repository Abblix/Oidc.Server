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
/// Represents the successful result of an authorized grant operation,
/// encapsulating the details of the authentication session and the authorization context.
/// </summary>
/// <param name="AuthSession">The authentication session associated with the grant, detailing the user's authenticated
/// state.</param>
/// <param name="Context">The context of the authorization process, providing specific details such as the client ID,
/// requested scopes, and any other relevant authorization parameters.</param>
public record AuthorizedGrant(AuthSession AuthSession, AuthorizationContext Context)
{
    /// <summary>
    /// An array of tokens that have been issued as part of this grant. This may include access tokens, refresh tokens
    /// or other types of tokens depending on the authorization flow and client request.
    /// </summary>
    public TokenInfo[]? IssuedTokens { get; init; }
}
