// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Features.MultiTenancy;

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
    /// <param name="tenant">The tenant whose keys are published.</param>
    /// <param name="logger">Logger used to warn when a private key is stripped before publication.</param>
    /// <returns>The signing keys followed by the asymmetric encryption public keys.</returns>
    public static async Task<JsonWebKey[]> GetPublishedKeysAsync(
        this IAuthServiceKeysProvider provider,
        TenantDefinition tenant,
        ILogger logger)
    {
        // Strip any private material first, then keep only keys that still have a publishable public half. A
        // symmetric key's only material is its shared secret, so once stripped it has nothing left to publish and
        // is dropped here: it can never reach the public JWKS, even if a provider hands it over carrying the secret.
        // Each surviving key is then stamped with its role's use, so every published key is explicitly labeled.
        var signingKeys = await provider.GetSigningKeys(tenant)
            .Select(key => PublicOnly(key, logger))
            .Where(key => key.HasPublicKey)
            .Select(key => key with { Usage = PublicKeyUsages.Signature })
            .ToArrayAsync();

        var encryptionKeys = await provider.GetEncryptionKeys(tenant)
            .Select(key => PublicOnly(key, logger))
            .Where(HasPublicHalf)
            .Select(key => key with { Usage = PublicKeyUsages.Encryption })
            .ToArrayAsync();

        return [..signingKeys, ..encryptionKeys];
    }

    /// <summary>
    /// The encryption keys of <paramref name="tenant"/> a client can encrypt an inbound JWE to, such as a request
    /// object (RFC 9101 section 6.1): those with a public half. OpenID Connect Discovery 1.0 section 3 has the
    /// <c>jwks_uri</c> document carry the encryption keys "used by RPs to encrypt requests to the Server" and forbids
    /// it any symmetric key value, so a symmetric server key reaches no client and opens no inbound JWE.
    /// </summary>
    /// <param name="provider">The provider of the service's keys.</param>
    /// <param name="tenant">The tenant whose keys are asked for.</param>
    /// <param name="includePrivateKeys">Whether to include private keys, as decryption needs.</param>
    public static IAsyncEnumerable<JsonWebKey> GetInboundEncryptionKeys(
        this IAuthServiceKeysProvider provider,
        TenantDefinition tenant,
        bool includePrivateKeys = false)
        => provider.GetEncryptionKeys(tenant, includePrivateKeys).Where(HasPublicHalf);

    /// <summary>
    /// The key management algorithms of <paramref name="algorithms"/> an inbound JWE to <paramref name="tenant"/> can
    /// be encrypted under: those one of its <see cref="GetInboundEncryptionKeys">inbound encryption keys</see> can be
    /// used with, by the algorithm it declares or, declaring none, by its material. The inbound decryption tries a
    /// key only under the same condition, so a client using an algorithm listed here meets a key that opens it.
    /// </summary>
    /// <param name="provider">The provider of the service's keys.</param>
    /// <param name="tenant">The tenant whose keys are asked for.</param>
    /// <param name="algorithms">The key management algorithms otherwise supported.</param>
    public static async Task<string[]> GetInboundKeyManagementAlgorithmsAsync(
        this IAuthServiceKeysProvider provider,
        TenantDefinition tenant,
        IEnumerable<string> algorithms)
    {
        var keys = await provider.GetInboundEncryptionKeys(tenant).ToArrayAsync();
        return algorithms.Where(algorithm => Array.Exists(keys, key => key.CanPerform(algorithm))).ToArray();
    }

    /// <summary>
    /// Whether the key keeps something to publish once stripped of private material: an asymmetric key does, a
    /// symmetric key, whose only material is its secret, does not.
    /// </summary>
    private static bool HasPublicHalf(JsonWebKey key) => key.Sanitize(includePrivateKeys: false).HasPublicKey;

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
