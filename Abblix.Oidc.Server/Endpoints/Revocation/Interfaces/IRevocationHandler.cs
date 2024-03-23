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

namespace Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;

/// <summary>
/// Defines a contract for handling revocation requests for access or refresh tokens as per OAuth 2.0 Token Revocation
/// specifications.  Ensures implementations can securely validate and process such requests to revoke tokens effectively.
/// </summary>
public interface IRevocationHandler
{
    /// <summary>
    /// Asynchronously handles a token revocation request by validating and then processing it to revoke
    /// the specified token.
    /// </summary>
    /// <param name="revocationRequest">The details of the revocation request, including the token to be revoked.</param>
    /// <param name="clientRequest">Additional information about the client making the revocation request,
    /// necessary for context-specific validation.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to a <see cref="RevocationResponse"/>, indicating the outcome of
    /// the revocation process. This could be a successful acknowledgment of the revocation or an error response
    /// if the request fails validation or processing.
    /// </returns>
    /// <remarks>
    /// This method is crucial for maintaining the security and integrity of the authorization server by allowing
    /// clients to revoke tokens that are no longer needed or may have been compromised.
    /// Implementations must ensure that revocation requests are authenticated and authorized before proceeding
    /// with token revocation, adhering to the OAuth 2.0 Token Revocation specification (RFC 7009).
    /// </remarks>
    Task<RevocationResponse> HandleAsync(
        RevocationRequest revocationRequest,
        ClientRequest clientRequest);
}
