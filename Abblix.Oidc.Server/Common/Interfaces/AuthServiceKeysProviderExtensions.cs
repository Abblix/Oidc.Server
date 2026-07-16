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
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Extension helpers for <see cref="IAuthServiceKeysProvider"/>.
/// </summary>
public static partial class AuthServiceKeysProviderExtensions
{
    /// <summary>
    /// Builds the public key set published at the JWKS endpoint: the signing public keys marked <c>use=sig</c>
    /// and the server's asymmetric encryption public keys marked <c>use=enc</c> so a client can encrypt a
    /// request object or other inbound JWE to the server (RFC 9101). A symmetric server key has no public half
    /// and is omitted; only sanitized public halves are ever published, never private or secret material.
    /// As a last-resort guard against a misbehaving key provider, any key still carrying private material is
    /// stripped to its public half before it enters the set and a warning is logged: the JWKS endpoint must
    /// never leak a private key, even if an upstream provider mistakenly returns one.
    /// </summary>
    /// <param name="provider">The provider of the service's signing and encryption keys.</param>
    /// <param name="logger">Logger used to warn when a private key is stripped before publication.</param>
    /// <returns>The signing keys followed by the asymmetric encryption public keys.</returns>
    public static async Task<JsonWebKey[]> GetPublishedKeysAsync(this IAuthServiceKeysProvider provider, ILogger logger)
    {
        // Strip any private material first, then keep only keys that still have a publishable public half. A
        // symmetric key's only material is its shared secret, so once stripped it has nothing left to publish and
        // is dropped here: it can never reach the public JWKS, even if a provider hands it over carrying the secret.
        // Each surviving key is then stamped with its role's use, so every published key is explicitly labelled.
        var signingKeys = await provider.GetSigningKeys()
            .Select(key => PublicOnly(key, logger))
            .Where(key => key.HasPublicKey)
            .Select(key => key with { Usage = PublicKeyUsages.Signature })
            .ToArrayAsync();

        var encryptionKeys = await provider.GetEncryptionKeys()
            .Select(key => PublicOnly(key, logger))
            .Where(key => key.HasPublicKey)
            .Select(key => key with { Usage = PublicKeyUsages.Encryption })
            .ToArrayAsync();

        return [..signingKeys, ..encryptionKeys];
    }

    /// <summary>
    /// Returns the key unchanged when it carries no private material; otherwise strips it to its public half
    /// and logs a warning. A defense-in-depth backstop at the publication boundary: the sanctioned providers
    /// already return public-only keys, so this fires only on a misconfigured or misbehaving one.
    /// </summary>
    private static JsonWebKey PublicOnly(JsonWebKey key, ILogger logger)
    {
        if (!key.HasPrivateKey)
            return key;

        LogPrivateKeyStrippedFromPublishedSet(logger, key.KeyId);
        return key.Sanitize(includePrivateKeys: false);
    }
}
