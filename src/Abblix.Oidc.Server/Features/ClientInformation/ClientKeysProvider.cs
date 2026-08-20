// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Facilitates the retrieval of JSON Web Keys (JWKs) for cryptographic operations, including encryption and signing.
/// This provider supports fetching keys from a client's JSON Web Key Set (JWKS) URL or directly from the client configuration.
/// </summary>
/// <param name="logger">Logger for capturing any operational logs.</param>
/// <param name="serviceProvider">Service provider used to resolve scoped dependencies like ISecureHttpFetcher.</param>
public class ClientKeysProvider(
    ILogger<ClientKeysProvider> logger,
    IServiceProvider serviceProvider) : IClientKeysProvider
{
    /// <summary>
    /// Retrieves the encryption keys associated with a specific client.
    /// </summary>
    /// <param name="clientInfo">Client information containing either JWKS or a JWKS URI.</param>
    /// <returns>A collection of encryption keys as an asynchronous enumerable.</returns>
    public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(ClientInfo clientInfo)
    {
        return GetKeys(clientInfo).Where(key => key.Usage is null or PublicKeyUsages.Encryption);
    }

    /// <summary>
    /// Retrieves the signing keys associated with a specific client.
    /// </summary>
    /// <param name="clientInfo">Client information containing either JWKS or a JWKS URI.</param>
    /// <returns>A collection of signing keys as an asynchronous enumerable.</returns>
    public IAsyncEnumerable<JsonWebKey> GetSigningKeys(ClientInfo clientInfo)
    {
        return GetKeys(clientInfo).Where(key => key.Usage is null or PublicKeyUsages.Signature);
    }

    /// <summary>
    /// Fetches the keys the client publishes, inline in its registration and at its JWKS URI, through the
    /// shared SSRF-protected and cached path.
    /// </summary>
    /// <param name="clientInfo">The client information specifying where to find the JWKS.</param>
    /// <returns>An asynchronous enumerable of <see cref="JsonWebKey"/>.</returns>
    private IAsyncEnumerable<JsonWebKey> GetKeys(ClientInfo clientInfo)
        => serviceProvider.ResolveKeysAsync(
            clientInfo.Jwks, clientInfo.JwksUri, logger, clientInfo.ClientId, KeySetOwners.Client);
}
