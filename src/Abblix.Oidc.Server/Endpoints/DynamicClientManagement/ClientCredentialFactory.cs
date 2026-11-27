// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Utils;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Coordinates credential generation by composing ID generation, secret generation, hashing, and expiration calculation.
/// Uses SHA-512 for strong cryptographic hashing while maintaining configurable secret length and expiration policies.
/// </summary>
/// <param name="clientIdGenerator">Generates the identifier of a client that proposes none.</param>
/// <param name="clientSecretGenerator">Generates the secret.</param>
/// <param name="hashService">Hashes the secret for storage.</param>
/// <param name="options">The server's settings, whose <see cref="NewClientOptions.ClientSecret"/> gives the length and
/// lifetime of a secret, read as it is generated.</param>
/// <param name="clock">Provides the issue time the secret's expiry counts from.</param>
public class ClientCredentialFactory(
    IClientIdGenerator clientIdGenerator,
    IClientSecretGenerator clientSecretGenerator,
    IHashService hashService,
    IOptionsMonitor<OidcOptions> options,
    TimeProvider clock) : IClientCredentialFactory
{
    /// <summary>
    /// Generates secrets conditionally based on authentication method to avoid unnecessary secret generation
    /// for public clients. Uses time-based expiration to enforce secret rotation policies.
    /// SHA-512 provides cryptographic strength while remaining compatible with HMAC-based client_secret_jwt.
    /// </summary>
    /// <param name="tokenEndpointAuthMethod">Determines whether secret generation is required.</param>
    /// <param name="clientId">The identifier to register the client under, or null for one the server generates.</param>
    /// <returns>
    /// Credentials containing both plain-text (for transmission) and hashed (for storage) secret formats,
    /// along with calculated expiration timestamp.
    /// </returns>
    public ClientCredentials Create(string tokenEndpointAuthMethod, string? clientId = null)
    {
        var finalClientId = clientId.HasValue() ? clientId : clientIdGenerator.GenerateClientId();

        switch (tokenEndpointAuthMethod)
        {
            case ClientAuthenticationMethods.ClientSecretBasic:
            case ClientAuthenticationMethods.ClientSecretPost:
            case ClientAuthenticationMethods.ClientSecretJwt:

                var secretOptions = options.CurrentValue.NewClientOptions.ClientSecret;
                var plainSecret = clientSecretGenerator.GenerateClientSecret(secretOptions.Length);
                var hashedSecret = hashService.Sha(HashAlgorithm.Sha512, plainSecret);
                var issuedAt = clock.GetUtcNow();
                var expiresAt = issuedAt + secretOptions.ExpiresAfter;

                return new ClientCredentials(finalClientId, plainSecret, hashedSecret, expiresAt);

            default:
                return new ClientCredentials(finalClientId, null, null, null);
        }
    }
}
