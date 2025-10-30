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
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Defines a contract for handling OAuth 2.0 token requests, encompassing validation, processing, and issuance
/// of tokens based on authorization grants.
/// </summary>
public interface ITokenHandler
{
    /// <summary>
    /// Asynchronously handles a token request, validating the request details and, if valid, processing it to issue,
    /// renew or exchange tokens according to OAuth 2.0 and OpenID Connect standards.
    /// </summary>
    /// <param name="tokenRequest">The token request containing essential parameters such as the grant type,
    /// client credentials, and other parameters pertinent to the token issuance process.</param>
    /// <param name="clientRequest">Supplementary information about the client making the request, necessary
    /// for performing contextual validation and ensuring the request complies with security policies.</param>
    /// <returns>
    /// A <see cref="Task"/> resulting in a <see cref="TokenResponse"/>, which either contains the issued tokens
    /// (access token, refresh token, ID token, etc.) in case of a successful request or details the reasons
    /// for request failure.
    /// </returns>
    /// <remarks>
    /// Implementations of this interface are critical to the secure and compliant functioning of an OAuth 2.0
    /// authorization server. They must ensure that only valid and authorized requests lead to the issuance of tokens,
    /// thereby maintaining the integrity and security of the authentication and authorization process.
    /// </remarks>
    Task<Result<TokenIssued, AuthError>> HandleAsync(TokenRequest tokenRequest, ClientRequest clientRequest);
}
