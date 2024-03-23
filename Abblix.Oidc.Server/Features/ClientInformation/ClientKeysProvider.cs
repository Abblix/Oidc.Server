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

using System.Net.Http.Json;
using Abblix.Jwt;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Facilitates the retrieval of JSON Web Keys (JWKs) for cryptographic operations, including encryption and signing.
/// This provider supports fetching keys from a client's JSON Web Key Set (JWKS) URL or directly from the client configuration.
/// </summary>
public class ClientKeysProvider : IClientKeysProvider
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ClientKeysProvider"/> class.
    /// </summary>
    /// <param name="logger">Logger for capturing any operational logs.</param>
    /// <param name="httpClientFactory">Factory for creating instances of <see cref="HttpClient"/> used to fetch JWKS from remote URLs.</param>
    public ClientKeysProvider(
        ILogger<ClientKeysProvider> logger,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    private readonly ILogger _logger;
    private readonly IHttpClientFactory _httpClientFactory;

    /// <summary>
    /// Retrieves the encryption keys associated with a specific client.
    /// </summary>
    /// <param name="clientInfo">Client information containing either JWKS or a JWKS URI.</param>
    /// <returns>A collection of encryption keys as an asynchronous enumerable.</returns>
    public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(ClientInfo clientInfo)
    {
        return GetKeys(clientInfo).WhereAsync(key => key.Usage == PublicKeyUsages.Encryption);
    }

    /// <summary>
    /// Retrieves the signing keys associated with a specific client.
    /// </summary>
    /// <param name="clientInfo">Client information containing either JWKS or a JWKS URI.</param>
    /// <returns>A collection of signing keys as an asynchronous enumerable.</returns>
    public IAsyncEnumerable<JsonWebKey> GetSigningKeys(ClientInfo clientInfo)
    {
        return GetKeys(clientInfo).WhereAsync(key => key.Usage == PublicKeyUsages.Signature);
    }

    /// <summary>
    /// Internally fetches keys from the client's JWKS or JWKS URI.
    /// </summary>
    /// <param name="clientInfo">The client information specifying where to find the JWKS.</param>
    /// <returns>An asynchronous enumerable of <see cref="JsonWebKey"/>.</returns>
    /// <remarks>
    /// This method attempts to retrieve keys directly from the client's configured JWKS. If a JWKS URI is provided,
    /// it fetches the JWKS from the remote URI. Logs warnings if the retrieval process fails.
    /// </remarks>
    private async IAsyncEnumerable<JsonWebKey> GetKeys(ClientInfo clientInfo)
    {
        // Directly yield keys from configured JWKS
        if (clientInfo.Jwks != null)
        {
            foreach (var key in clientInfo.Jwks.Keys)
                yield return key;
        }

        // Attempt to fetch keys from JWKS URI
        var jwksUri = clientInfo.JwksUri;
        if (jwksUri == null)
            yield break;

        JsonWebKeySet? jwks = null;
        try
        {
            jwks = await _httpClientFactory.CreateClient().GetFromJsonAsync<JsonWebKeySet>(jwksUri);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unable to get JWKS from specified URI: {JwksUri}", jwksUri);
        }

        if (jwks == null)
            yield break;

        foreach (var key in jwks.Keys)
            yield return key;
    }
}
