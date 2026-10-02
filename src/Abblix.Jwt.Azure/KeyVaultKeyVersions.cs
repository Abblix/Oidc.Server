// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Azure.Security.KeyVault.Keys also declares a JsonWebKey; alias the namespace so the bare JsonWebKey stays the
// Abblix.Jwt one, which the .Apply extension produces.
using KeyVault = Azure.Security.KeyVault.Keys;

namespace Abblix.Jwt.Azure;

/// <summary>
/// Reads the enabled versions of a Key Vault key as public-only JWKs. Key Vault lists version metadata but not
/// the public key, so each version's key is fetched.
/// </summary>
internal static class KeyVaultKeyVersions
{
    /// <summary>
    /// Every enabled version of <paramref name="keyName"/>, each carrying the version-specific <c>kid</c>
    /// (<c>&lt;name&gt;/&lt;version&gt;</c>) and the version's creation time.
    /// </summary>
    public static async Task<List<KeyVersion>> ReadAsync(
        KeyVault.KeyClient keyClient, string keyName, CancellationToken cancellationToken)
    {
        var versions = new List<KeyVersion>();
        await foreach (var properties in keyClient.GetPropertiesOfKeyVersionsAsync(keyName, cancellationToken))
        {
            // A disabled version (rotated out, or not yet enabled) must not be published or produced with.
            if (properties.Enabled != true)
                continue;

            // A creation time is not decoration: it decides which version signs and when a rotation takes over.
            // Substituting a default would date the version to year one, so it could never be chosen to produce
            // with and would read as long past its propagation window. A version whose age is unknown cannot be
            // ordered, so it fails loud rather than sorting wrong, which is what the Vault client does too.
            var createdAt = properties.CreatedOn
                ?? throw new InvalidOperationException(
                    $"Key Vault reported no creation time for '{keyName}/{properties.Version}', so its place in " +
                    "the rotation cannot be determined.");

            var key = await keyClient.GetKeyAsync(keyName, properties.Version, cancellationToken);
            var publicKey = Import(key.Value.Key) with { KeyId = $"{keyName}/{properties.Version}" };
            versions.Add(new KeyVersion(publicKey, createdAt));
        }

        return versions;
    }

    /// <summary>The public-only JWK for <paramref name="webKey"/>.</summary>
    /// <exception cref="NotSupportedException">The key is neither EC nor RSA.</exception>
    public static JsonWebKey Import(KeyVault.JsonWebKey webKey)
    {
        if (webKey.KeyType == KeyVault.KeyType.Ec || webKey.KeyType == KeyVault.KeyType.EcHsm)
        {
            using var ecdsa = webKey.ToECDsa();
            return new EllipticCurveJsonWebKey().Apply(ecdsa.ExportParameters(false));
        }

        if (webKey.KeyType == KeyVault.KeyType.Rsa || webKey.KeyType == KeyVault.KeyType.RsaHsm)
        {
            using var rsa = webKey.ToRSA();
            return new RsaJsonWebKey().Apply(rsa.ExportParameters(false));
        }

        throw new NotSupportedException($"The Azure Key Vault store does not publish key type '{webKey.KeyType}'.");
    }
}
