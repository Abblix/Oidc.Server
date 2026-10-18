// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


using System.Security.Cryptography;

namespace Abblix.Jwt;

/// <summary>
/// Converts between an RSA JSON Web Key and the platform's RSA types, and measures the key's modulus.
/// </summary>
public static class RsaJsonWebKeyExtensions
{
    /// <summary>
    /// Applies RSA parameters to an RsaJsonWebKey.
    /// </summary>
    /// <param name="jwk">The RsaJsonWebKey to which the RSA parameters are to be applied.</param>
    /// <param name="parameters">The RSAParameters providing the RSA key information.</param>
    /// <returns>The updated RsaJsonWebKey with applied RSA parameters.</returns>
    public static RsaJsonWebKey Apply(this RsaJsonWebKey jwk, RSAParameters parameters)
    {
        jwk.Exponent = parameters.Exponent;
        jwk.Modulus = parameters.Modulus;

        jwk.PrivateExponent = parameters.D;
        jwk.FirstPrimeFactor = parameters.P;
        jwk.SecondPrimeFactor = parameters.Q;
        jwk.FirstFactorCrtExponent = parameters.DP;
        jwk.SecondFactorCrtExponent = parameters.DQ;
        jwk.FirstCrtCoefficient = parameters.InverseQ;

        return jwk;
    }

    /// <summary>
    /// Converts an RsaJsonWebKey to an RSA object, which represents an RSA public and private key pair or just a public key.
    /// </summary>
    /// <param name="key">The RsaJsonWebKey to be converted.</param>
    /// <returns>An RSA object based on the provided RsaJsonWebKey.</returns>
    public static RSA ToRsa(this RsaJsonWebKey key)
    {
        var rsa = RSA.Create();
        rsa.ImportParameters(key.ToRsaParameters());
        return rsa;
    }

    /// <summary>
    /// The real bit length of the key's modulus, ignoring any leading zero octets.
    /// </summary>
    /// <remarks>
    /// <c>RSA.KeySize</c> is not this number, and how far it differs depends on the platform. It reports
    /// the key as the importer built it: Windows CNG keeps a left-padded modulus at its padded length and
    /// reports twice the real strength, while Linux (OpenSSL) strips the leading zeros and reports the
    /// true one. So a size check written against that property refuses a downgraded key on one operating
    /// system and admits it on another - which is a worse failure than either, because the deployment
    /// that admits it looks identical to the one that does not, and the forgery arrives later from
    /// whoever factored the real modulus.
    /// <para>
    /// Measuring the modulus itself removes the platform from the question. It is also never larger than
    /// <c>RSA.KeySize</c>, so switching to it can only add refusals, never remove one.
    /// </para>
    /// <para>
    /// RFC 7518 Section 2 requires the minimal encoding - "The octet sequence MUST utilize the minimum
    /// number of octets needed to represent the value" - which is what this measurement follows. Padding
    /// far enough to matter is NOT something a library does by accident: the one benign quirk the
    /// specification records is a single extra zero octet (Section 6.3.1.1, "returning 257 octets for a
    /// 2048-bit key"), and one octet moves neither check in either direction. Sixty-four of them is a
    /// malformed or hostile JWKS entry.
    /// </para>
    /// <para>
    /// The leading octet contributes only the bits from its own highest set bit down, which is what makes
    /// this the modulus's true length rather than a rounded-up octet count.
    /// </para>
    /// </remarks>
    public static int ModulusBitLength(this RsaJsonWebKey key)
    {
        var modulus = key.Modulus;
        if (modulus is null)
            return 0;

        var first = 0;
        while (first < modulus.Length && modulus[first] == 0)
            first++;

        if (first == modulus.Length)
            return 0;

        var bitsInLeadingOctet = 8;
        for (var mask = 0x80; mask != 0 && (modulus[first] & mask) == 0; mask >>= 1)
            bitsInLeadingOctet--;

        return (modulus.Length - first - 1) * 8 + bitsInLeadingOctet;
    }

    /// <summary>
    /// Converts an RsaJsonWebKey to RSAParameters, which represent the key parameters used in RSA cryptographic operations.
    /// </summary>
    /// <param name="key">The RsaJsonWebKey to be converted.</param>
    /// <returns>An RSAParameters object based on the provided RsaJsonWebKey.</returns>
    public static RSAParameters ToRsaParameters(this RsaJsonWebKey key) => new()
    {
        Modulus = key.Modulus,
        Exponent = key.Exponent,
        D = key.PrivateExponent,
        P = key.FirstPrimeFactor,
        Q = key.SecondPrimeFactor,
        DP = key.FirstFactorCrtExponent,
        DQ = key.SecondFactorCrtExponent,
        InverseQ = key.FirstCrtCoefficient,
    };
}
