// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography.X509Certificates;

namespace Abblix.Jwt;

/// <summary>
/// Converts an X.509 certificate into a JSON Web Key: its public key, its private key when asked for, the
/// <c>use</c> its Key Usage extension permits, and the certificate itself.
/// </summary>
public static class CertificateJsonWebKeyExtensions
{
    /// <summary>
    /// Converts an X509Certificate2 to a JsonWebKey. The private keys can be optionally included in the conversion.
    /// </summary>
    /// <param name="certificate">The X509Certificate2 to convert.</param>
    /// <param name="includePrivateKeys">Indicates whether to include private keys in the conversion.</param>
    /// <returns>A JsonWebKey representing the certificate.</returns>
    public static JsonWebKey ToJsonWebKey(this X509Certificate2 certificate, bool includePrivateKeys = false)
    {
        // Try ECDSA first
        var ecdsaPublicKey = certificate.GetECDsaPublicKey();
        if (ecdsaPublicKey != null)
        {
            var ecdsaPrivateKey = includePrivateKeys ? certificate.GetECDsaPrivateKey() : null;

            var jwk = new EllipticCurveJsonWebKey
            {
                Usage = certificate.GetKeyUsage(),
                KeyId = certificate.Thumbprint,
            }
                .Apply(ecdsaPublicKey.ExportParameters(false))
                .Apply(certificate);

            if (ecdsaPrivateKey != null)
            {
                jwk = jwk.Apply(ecdsaPrivateKey.ExportParameters(true));
            }

            return jwk;
        }

        // Fall back to RSA
        var rsaPublicKey = certificate.GetRSAPublicKey();
        if (rsaPublicKey != null)
        {
            var rsaPrivateKey = includePrivateKeys ? certificate.GetRSAPrivateKey() : null;

            var jwk = new RsaJsonWebKey
            {
                Usage = certificate.GetKeyUsage(),
                KeyId = certificate.Thumbprint,
            }.Apply(rsaPublicKey.ExportParameters(false)).Apply(certificate);

            if (rsaPrivateKey != null)
            {
                jwk = jwk.Apply(rsaPrivateKey.ExportParameters(true));
            }

            return jwk;
        }

        throw new InvalidOperationException($"Certificate does not contain a supported public key algorithm");
    }

    /// <summary>
    /// Derives the JWK <c>use</c> value from a certificate's Key Usage extension. A certificate that permits both
    /// signing and encryption maps to no <c>use</c> (<c>null</c>): RFC 7517 section 4.2 makes <c>use</c> a single value,
    /// so an unrestricted key is expressed by omitting <c>use</c>, never by a multi-valued string. A certificate
    /// with no Key Usage extension defaults to signing.
    /// </summary>
    private static string? GetKeyUsage(this X509Certificate2 certificate)
    {
        const string defaultUsage = PublicKeyUsages.Signature;

        var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (keyUsage == null)
            return defaultUsage;

        var sig = keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature);

        // Either encipherment flag marks an encryption key. HasFlag(A | B) would demand both flags, so test the bits.
        var enc =
            keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment) ||
            keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DataEncipherment);

        return (sig, enc) switch
        {
            (true, true) => null, // permits both: omit use per RFC 7517 section 4.2, never a multi-valued "sig enc"
            (true, false) => PublicKeyUsages.Signature,
            (false, true) => PublicKeyUsages.Encryption,
            _ => defaultUsage,
        };
    }

    /// <summary>
    /// Applies X509Certificate2 properties to a JsonWebKey.
    /// </summary>
    /// <typeparam name="T">The type of JsonWebKey (must be a subclass).</typeparam>
    /// <param name="jwk">The JsonWebKey to which the certificate properties are to be applied.</param>
    /// <param name="certificate">The X509Certificate2 providing the properties.</param>
    /// <returns>The updated JsonWebKey with applied certificate properties.</returns>
    public static T Apply<T>(this T jwk, X509Certificate2 certificate) where T : JsonWebKey
    {
        jwk.Certificates = [certificate.RawData];
        jwk.Thumbprint = certificate.GetCertHash();
        return jwk;
    }
}
