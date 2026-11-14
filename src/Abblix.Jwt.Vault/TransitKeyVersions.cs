// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace Abblix.Jwt.Vault;

/// <summary>
/// Reads the versions of a Transit key from its key read: each version's public half arrives as a PEM
/// (SubjectPublicKeyInfo) and leaves as a public-only JWK of the matching type.
/// </summary>
internal static class TransitKeyVersions
{
    /// <summary>
    /// Every version under <paramref name="data"/>, each carrying the version-specific <c>kid</c>
    /// (<c>&lt;name&gt;:&lt;version&gt;</c>) and the version's creation time.
    /// </summary>
    /// <param name="data">The <c>data</c> member of Transit's answer to <c>keys/{name}</c>.</param>
    /// <param name="keyName">The Transit key name.</param>
    public static IEnumerable<KeyVersion> Read(JsonElement data, string keyName)
    {
        var keyType = data.GetProperty("type").GetString()!;

        // Transit returns every version under "keys" as { "<version>": { public_key, creation_time } }. Publish
        // them all so a rotation overlaps; the kid names the version so a later sign/unwrap addresses it exactly.
        foreach (var version in data.GetProperty("keys").EnumerateObject())
        {
            var pem = version.Value.GetProperty("public_key").GetString()!;
            var createdAt = DateTimeOffset.Parse(
                version.Value.GetProperty("creation_time").GetString()!,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind);
            var publicKey = Import(keyType, pem) with { KeyId = $"{keyName}:{version.Name}" };
            yield return new KeyVersion(publicKey, createdAt);
        }
    }

    /// <summary>
    /// The public-only JWK for <paramref name="pem"/>, typed by the Transit key type it was published under.
    /// </summary>
    /// <exception cref="NotSupportedException">The key type is neither ECDSA nor RSA.</exception>
    private static JsonWebKey Import(string keyType, string pem)
    {
        if (keyType.StartsWith(KeyFamilyTypes.Ecdsa, StringComparison.Ordinal))
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);
            return new EllipticCurveJsonWebKey().Apply(ecdsa.ExportParameters(false));
        }

        if (keyType.StartsWith(KeyFamilyTypes.Rsa, StringComparison.Ordinal))
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return new RsaJsonWebKey().Apply(rsa.ExportParameters(false));
        }

        throw new NotSupportedException($"The Vault Transit store does not publish key type '{keyType}'.");
    }

    /// <summary>
    /// Transit reports the key family in the "type" field ("ecdsa-p256", "rsa-2048"): match on the family prefix,
    /// not the exact curve or modulus size.
    /// </summary>
    private static class KeyFamilyTypes
    {
        public const string Ecdsa = "ecdsa";
        public const string Rsa = "rsa";
    }
}
