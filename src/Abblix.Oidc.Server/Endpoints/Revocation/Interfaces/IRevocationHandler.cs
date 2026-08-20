// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

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
    /// A <see cref="Task"/> that resolves to a <see cref="Result{TSuccess, TFailure}"/> containing either
    /// <see cref="TokenRevoked"/> on success or <see cref="OidcError"/> on failure.
    /// </returns>
    /// <remarks>
    /// This method is crucial for maintaining the security and integrity of the authorization server by allowing
    /// clients to revoke tokens that are no longer needed or may have been compromised.
    /// Implementations must ensure that revocation requests are authenticated and authorized before proceeding
    /// with token revocation, adhering to the OAuth 2.0 Token Revocation specification (RFC 7009).
    /// </remarks>
    Task<Result<TokenRevoked, OidcError>> HandleAsync(
        RevocationRequest revocationRequest,
        ClientRequest clientRequest);
}
