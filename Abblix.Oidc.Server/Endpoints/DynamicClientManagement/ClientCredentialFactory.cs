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

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Coordinates credential generation by composing ID generation, secret generation, hashing, and expiration calculation.
/// Uses SHA-512 for strong cryptographic hashing while maintaining configurable secret length and expiration policies.
/// </summary>
public class ClientCredentialFactory(
    IClientIdGenerator clientIdGenerator,
    IClientSecretGenerator clientSecretGenerator,
    IHashService hashService,
    NewClientOptions options,
    TimeProvider clock) : IClientCredentialFactory
{
    /// <summary>
    /// Generates secrets conditionally based on authentication method to avoid unnecessary secret generation
    /// for public clients. Uses time-based expiration to enforce secret rotation policies.
    /// SHA-512 provides cryptographic strength while remaining compatible with HMAC-based client_secret_jwt.
    /// </summary>
    /// <param name="tokenEndpointAuthMethod">Determines whether secret generation is required.</param>
    /// <param name="clientId">Allows external client ID assignment for pre-registration scenarios.</param>
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

                var plainSecret = clientSecretGenerator.GenerateClientSecret(options.ClientSecret.Length);
                var hashedSecret = hashService.Sha(HashAlgorithm.Sha512, plainSecret);
                var issuedAt = clock.GetUtcNow();
                var expiresAt = issuedAt + options.ClientSecret.ExpiresAfter;

                return new ClientCredentials(finalClientId, plainSecret, hashedSecret, expiresAt);

            default:
                return new ClientCredentials(finalClientId, null, null, null);
        }
    }
}
