// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>Generates RSA JSON Web Keys, at the key size floor RFC 7518 sets or above it.</summary>
internal static class RsaJsonWebKeyFactory
{
    /// <inheritdoc cref="JsonWebKeyFactory.CreateRsa"/>
    public static RsaJsonWebKey CreateRsa(string usage, string? algorithm, int keySize)
    {
        if (usage is not (PublicKeyUsages.Signature or PublicKeyUsages.Encryption))
        {
            throw new ArgumentException(
                $"Invalid usage specified. Valid options are '{PublicKeyUsages.Signature}' for signing" +
                $" or '{PublicKeyUsages.Encryption}' for encryption.",
                nameof(usage));
        }

        if (keySize < KeySizeFloors.MinimumRsaKeyBits)
        {
            throw new ArgumentException(
                $"An RSA key of {keySize} bits cannot be used for JOSE: RFC 7518 requires at least " +
                $"{KeySizeFloors.MinimumRsaKeyBits}, and this library refuses to sign or encrypt " +
                "with anything smaller. Raise the configured key size.",
                nameof(keySize));
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
}
