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
