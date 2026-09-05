// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using System.Text.Json;

namespace Abblix.Jwt.Azure.UnitTests;

/// <summary>Builders for the Key Vault JSON payloads the stub transport returns.</summary>
internal static class AzureResponses
{
    public static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>A public-only RSA key bundle, the shape <c>KeyClient.GetKey</c> and the crypto client's
    /// just-in-time key download expect.</summary>
    public static string KeyBundle(Uri vaultUri, string keyName, RSAParameters publicKey)
        => JsonSerializer.Serialize(new
        {
            key = new
            {
                kid = $"{vaultUri}keys/{keyName}/v1",
                kty = "RSA",
                key_ops = new[] { "sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey" },
                n = Base64Url(publicKey.Modulus!),
                e = Base64Url(publicKey.Exponent!),
            },
            attributes = new { enabled = true },
        });

    /// <summary>A public-only P-256 EC key bundle, the shape the SDK expects for an EC key.</summary>
    public static string EcKeyBundle(Uri vaultUri, string keyName, ECParameters publicKey, string curve = "P-256")
        => JsonSerializer.Serialize(new
        {
            key = new
            {
                kid = $"{vaultUri}keys/{keyName}/v1",
                kty = "EC",
                crv = curve,
                key_ops = new[] { "sign", "verify" },
                x = Base64Url(publicKey.Q.X!),
                y = Base64Url(publicKey.Q.Y!),
            },
            attributes = new { enabled = true },
        });

    /// <summary>A sign or decrypt result, both shaped <c>{ kid, value }</c> with a base64url value.</summary>
    public static string CryptoResult(Uri vaultUri, string keyName, byte[] value)
        => JsonSerializer.Serialize(new { kid = $"{vaultUri}keys/{keyName}/v1", value = Base64Url(value) });

    /// <summary>A "get key versions" page: each version's identifier, creation time (Unix seconds) and enabled
    /// flag, the shape <c>KeyClient.GetPropertiesOfKeyVersions</c> pages over.</summary>
    public static string KeyVersionsList(Uri vaultUri, string keyName, params (string Version, long CreatedUnix)[] versions)
        => KeyVersionsList(
            vaultUri, keyName, versions.Select(v => (v.Version, (long?)v.CreatedUnix, true)).ToArray());

    /// <summary>
    /// The same page, with the two attributes an operator can actually change: whether a version is enabled, and
    /// whether the vault reports a creation time at all.
    /// </summary>
    /// <remarks>
    /// Both are load-bearing rather than decorative. Disabling a version is how a compromised key is taken out of
    /// service, and a version with no creation time cannot be placed in the rotation order. Neither can be
    /// expressed by the simpler overload, which is why the paths that honour them went untested.
    /// </remarks>
    public static string KeyVersionsList(
        Uri vaultUri, string keyName, params (string Version, long? CreatedUnix, bool Enabled)[] versions)
        => JsonSerializer.Serialize(new
        {
            value = versions.Select(version => new
            {
                kid = $"{vaultUri}keys/{keyName}/{version.Version}",

                // A vault that reports no creation time omits the member; sending null is not the same shape.
                attributes = version.CreatedUnix is { } created
                    ? new Dictionary<string, object> { ["enabled"] = version.Enabled, ["created"] = created }
                    : new Dictionary<string, object> { ["enabled"] = version.Enabled },
            }).ToArray(),
            nextLink = (string?)null,
        });
}