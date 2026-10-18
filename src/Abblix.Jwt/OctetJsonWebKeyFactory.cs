// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


using System.Security.Cryptography;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>Generates symmetric JSON Web Keys for HMAC signing.</summary>
internal static class OctetJsonWebKeyFactory
{
    /// <inheritdoc cref="JsonWebKeyFactory.CreateHmac"/>
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
}
