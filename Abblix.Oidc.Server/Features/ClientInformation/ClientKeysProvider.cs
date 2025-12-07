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
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
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
        return GetKeys(clientInfo).Where(key => key.Usage == PublicKeyUsages.Encryption);
    }

    /// <summary>
    /// Retrieves the signing keys associated with a specific client.
    /// </summary>
    /// <param name="clientInfo">Client information containing either JWKS or a JWKS URI.</param>
    /// <returns>A collection of signing keys as an asynchronous enumerable.</returns>
    public IAsyncEnumerable<JsonWebKey> GetSigningKeys(ClientInfo clientInfo)
    {
        return GetKeys(clientInfo).Where(key => key.Usage == PublicKeyUsages.Signature);
    }

    /// <summary>
    /// Internally fetches keys from the client's JWKS or JWKS URI with SSRF protection.
    /// </summary>
    /// <param name="clientInfo">The client information specifying where to find the JWKS.</param>
    /// <returns>An asynchronous enumerable of <see cref="JsonWebKey"/>.</returns>
    /// <remarks>
    /// This method attempts to retrieve keys directly from the client's configured JWKS. If a JWKS URI is provided,
    /// it fetches the JWKS from the remote URI using ISecureHttpFetcher for SSRF protection.
    /// Logs warnings if the retrieval process fails.
    /// </remarks>
    private async IAsyncEnumerable<JsonWebKey> GetKeys(ClientInfo clientInfo)
    {
        // Directly yield keys from configured JWKS
        if (clientInfo.Jwks != null)
        {
            foreach (var key in clientInfo.Jwks.Keys)
                yield return key;
        }

        // Attempt to fetch keys from JWKS URI with SSRF protection
        var jwksUri = clientInfo.JwksUri;
        if (jwksUri == null)
            yield break;

        logger.LogDebug("Fetching JWKS for client {ClientId} from {JwksUri}", clientInfo.ClientId, jwksUri);

        using var scope = serviceProvider.CreateScope();
        var secureFetcher = scope.ServiceProvider.GetRequiredService<ISecureHttpFetcher>();

        var result = await secureFetcher.FetchAsync<JsonWebKeySet>(jwksUri);

        var jwksKeys = result.Match(
            jwks =>
            {
                if (jwks is { Keys: { Length: > 0 } keys })
                    return keys.ToAsyncEnumerable();

                logger.LogWarning("JWKS for client {ClientId} from {JwksUri} is empty or invalid",
                    clientInfo.ClientId, jwksUri);

                return AsyncEnumerable.Empty<JsonWebKey>();

            },
            error =>
            {
                logger.LogWarning("Failed to fetch JWKS for client {ClientId} from {JwksUri}: {Error}",
                    clientInfo.ClientId, jwksUri, error.ErrorDescription);

                return AsyncEnumerable.Empty<JsonWebKey>();
            });

        await foreach (var key in jwksKeys)
        {
            yield return key;
        }
    }
}
