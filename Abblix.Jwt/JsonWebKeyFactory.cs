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

using System.Security.Cryptography;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// A factory for creating JsonWebKey objects for various cryptographic key types.
/// Supports RSA, Elliptic Curve, and symmetric (HMAC) keys for JWT operations.
/// </summary>
public static class JsonWebKeyFactory
{
    /// <summary>
    /// Creates an RSA JsonWebKey with a specified algorithm.
    /// </summary>
    /// <param name="usage">The intended usage of the key, typically 'sig' for signing or 'enc' for encryption.</param>
    /// <param name="algorithm">The signing or encryption algorithm. Key size is determined automatically based on the algorithm.</param>
    /// <param name="keySize">The size of the RSA key in bits. If null, determined by algorithm (defaults to 2048).</param>
    /// <returns>A <see cref="RsaJsonWebKey"/> configured for the specified algorithm.</returns>
    public static RsaJsonWebKey CreateRsa(string usage, string? algorithm = null, int keySize = 2048)
    {
        if (usage is not (PublicKeyUsages.Signature or PublicKeyUsages.Encryption))
        {
            throw new ArgumentException(
                $"Invalid usage specified. Valid options are '{PublicKeyUsages.Signature}' for signing or '{PublicKeyUsages.Encryption}' for encryption.",
                nameof(usage));
        }

        using var rsa = RSA.Create();
        rsa.KeySize = keySize;
        var parameters = rsa.ExportParameters(true);

        var key = new RsaJsonWebKey
        {
            KeyId = parameters.ToKeyId(),
            Algorithm = algorithm,
            Usage = usage,
            Exponent = parameters.Exponent,
            Modulus = parameters.Modulus,
            PrivateExponent = parameters.D,
            FirstPrimeFactor = parameters.P,
            SecondPrimeFactor = parameters.Q,
            FirstFactorCrtExponent = parameters.DP,
            SecondFactorCrtExponent = parameters.DQ,
            FirstCrtCoefficient = parameters.InverseQ,
        };

        return key;

    }

    /// <summary>
    /// Creates an Elliptic Curve JsonWebKey with a specified curve.
    /// </summary>
    /// <param name="curve">The elliptic curve to use. Common values: P-256, P-384, P-521.</param>
    /// <param name="algorithm">The signing algorithm. Common values: ES256, ES384, ES512.</param>
    /// <returns>A <see cref="EllipticCurveJsonWebKey"/> suitable for ECDSA signing operations.</returns>
    public static EllipticCurveJsonWebKey CreateEllipticCurve(string curve, string algorithm)
    {
        var ecCurve = curve switch
        {
            EllipticCurveTypes.P256 => ECCurve.NamedCurves.nistP256,
            EllipticCurveTypes.P384 => ECCurve.NamedCurves.nistP384,
            EllipticCurveTypes.P521 => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentException($"Unsupported elliptic curve: {curve}", nameof(curve))
        };

        using var ecdsa = ECDsa.Create(ecCurve);
        var parameters = ecdsa.ExportParameters(true);

        var key = new EllipticCurveJsonWebKey
        {
            KeyId = ComputeEcKeyId(parameters),
            Algorithm = algorithm,
            Usage = PublicKeyUsages.Signature,
            Curve = curve,
            X = parameters.Q.X,
            Y = parameters.Q.Y,
            PrivateKey = parameters.D,
        };

        return key;
    }

    /// <summary>
    /// Creates a symmetric (Octet) JsonWebKey for HMAC signing.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm. Common values: HS256, HS384, HS512.</param>
    /// <param name="keySize">The key size in bytes. Defaults based on algorithm: HS256=32, HS384=48, HS512=64.</param>
    /// <returns>A <see cref="OctetJsonWebKey"/> suitable for HMAC signing operations.</returns>
    public static OctetJsonWebKey CreateHmac(string algorithm, int? keySize = null)
    {
        var size = keySize ?? algorithm switch
        {
            SigningAlgorithms.HS256 => 32, // 256 bits
            SigningAlgorithms.HS384 => 48, // 384 bits
            SigningAlgorithms.HS512 => 64, // 512 bits
            _ => throw new ArgumentException($"Unsupported HMAC algorithm: {algorithm}", nameof(algorithm))
        };

        var keyValue = CryptoRandom.GetRandomBytes(size);

        var key = new OctetJsonWebKey
        {
            KeyId = SHA256.HashData(keyValue).ToHexString(),
            Algorithm = algorithm,
            Usage = PublicKeyUsages.Signature,
            KeyValue = keyValue,
        };

        return key;
    }

    private static string ToKeyId(this RSAParameters parameters)
    {
        var keyMaterial = (parameters.Modulus, parameters.Exponent) switch
        {
            ({} modulus, {} exponent) => modulus.Concat(exponent),
            ({} modulus, null) => modulus,
            (null, {} exponent) => exponent,
            (null, null) => Array.Empty<byte>(),
        };

        return SHA256.HashData(keyMaterial).ToHexString();
    }

    private static string ComputeEcKeyId(ECParameters parameters)
    {
        var keyMaterial = (parameters.Q.X, parameters.Q.Y) switch
        {
            ({} x, {} y) => x.Concat(y),
            ({} x, null) => x,
            (null, {} y) => y,
            (null, null) => Array.Empty<byte>(),
        };

        return SHA256.HashData(keyMaterial).ToHexString();
    }

}
