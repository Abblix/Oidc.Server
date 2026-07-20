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
    public static string EcKeyBundle(Uri vaultUri, string keyName, ECParameters publicKey)
        => JsonSerializer.Serialize(new
        {
            key = new
            {
                kid = $"{vaultUri}keys/{keyName}/v1",
                kty = "EC",
                crv = "P-256",
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
        => JsonSerializer.Serialize(new
        {
            value = versions.Select(version => new
            {
                kid = $"{vaultUri}keys/{keyName}/{version.Version}",
                attributes = new { enabled = true, created = version.CreatedUnix },
            }).ToArray(),
            nextLink = (string?)null,
        });
}