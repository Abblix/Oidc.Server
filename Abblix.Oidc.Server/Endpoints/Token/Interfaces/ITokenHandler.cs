// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Model;

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
    Task<TokenResponse> HandleAsync(TokenRequest tokenRequest, ClientRequest clientRequest);
}
