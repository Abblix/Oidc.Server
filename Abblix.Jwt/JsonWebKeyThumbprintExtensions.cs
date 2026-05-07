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

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Abblix.Jwt;

/// <summary>
/// Computes the JWK Thumbprint of a <see cref="JsonWebKey"/> per RFC 7638: a SHA-256 hash
/// over a canonical-JSON form that contains only the required members for the key's
/// <c>kty</c>, in lexicographic order, with no whitespace.
/// </summary>
/// <remarks>
/// The JWK Thumbprint is the value used by OAuth 2.0 DPoP (RFC 9449) for the
/// <c>cnf.jkt</c> claim and the <c>dpop_jkt</c> request parameter. It is computed at
/// runtime from the public-key material; it is not a stored member on the JWK and is
/// distinct from the X.509 cert thumbprints <c>x5t</c> (RFC 7517 §4.8) and
/// <c>x5t#S256</c> (RFC 7517 §4.9), which hash the certificate, not the key.
/// </remarks>
public static class JsonWebKeyThumbprintExtensions
{
    /// <summary>
    /// Computes the JWK Thumbprint of <paramref name="key"/> per RFC 7638 §3 as the raw
    /// 32-byte SHA-256 digest of the canonical-JSON form.
    /// </summary>
    /// <param name="key">The JWK whose thumbprint to compute.</param>
    /// <returns>The 32-byte SHA-256 digest.</returns>
    /// <exception cref="InvalidOperationException">A required member (per
    /// RFC 7638 §3.2) is missing for the concrete <see cref="JsonWebKey"/> subtype.</exception>
    /// <exception cref="NotSupportedException">The concrete <see cref="JsonWebKey"/>
    /// subtype is not handled by this implementation.</exception>
    public static byte[] ComputeJwkThumbprint(this JsonWebKey key)
    {
        var canonical = key switch
        {
            EllipticCurveJsonWebKey ec => CanonicalEc(ec),
            RsaJsonWebKey rsa => CanonicalRsa(rsa),
            OctetJsonWebKey oct => CanonicalOct(oct),
            _ => throw new NotSupportedException(
                $"JWK Thumbprint is not implemented for key type {key.GetType().Name}."),
        };

        return SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
    }

    /// <summary>
    /// Computes the JWK Thumbprint of <paramref name="key"/> per RFC 7638 §3 and returns
    /// the base64url-encoded form, which is the wire shape used by DPoP <c>cnf.jkt</c>
    /// and the <c>dpop_jkt</c> authorization-request parameter.
    /// </summary>
    public static string ComputeJwkThumbprintBase64Url(this JsonWebKey key)
        => Base64Url.EncodeToString(key.ComputeJwkThumbprint());

    // The canonical strings below interpolate Base64Url-encoded byte values and the curve
    // identifier verbatim. All three are restricted to characters that require no JSON
    // escaping (Base64Url alphabet, ASCII letters/digits, hyphen), so the result is
    // RFC 8259 compliant by construction.

    private static string CanonicalEc(EllipticCurveJsonWebKey k)
    {
        var crv = k.Curve ?? throw new InvalidOperationException(
            "JWK Thumbprint requires the 'crv' member for an EC key.");
        var x = k.X ?? throw new InvalidOperationException(
            "JWK Thumbprint requires the 'x' member for an EC key.");
        var y = k.Y ?? throw new InvalidOperationException(
            "JWK Thumbprint requires the 'y' member for an EC key.");

        return $$"""{"crv":"{{crv}}","kty":"EC","x":"{{Base64Url.EncodeToString(x)}}","y":"{{Base64Url.EncodeToString(y)}}"}""";
    }

    private static string CanonicalRsa(RsaJsonWebKey k)
    {
        var e = k.Exponent ?? throw new InvalidOperationException(
            "JWK Thumbprint requires the 'e' member for an RSA key.");
        var n = k.Modulus ?? throw new InvalidOperationException(
            "JWK Thumbprint requires the 'n' member for an RSA key.");

        return $$"""{"e":"{{Base64Url.EncodeToString(e)}}","kty":"RSA","n":"{{Base64Url.EncodeToString(n)}}"}""";
    }

    private static string CanonicalOct(OctetJsonWebKey k)
    {
        var keyValue = k.KeyValue ?? throw new InvalidOperationException(
            "JWK Thumbprint requires the 'k' member for an oct key.");

        return $$"""{"k":"{{Base64Url.EncodeToString(keyValue)}}","kty":"oct"}""";
    }
}
