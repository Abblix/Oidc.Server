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
    public static OctetJsonWebKey CreateHmac(string algorithm, int? keySize)
    {
        // By default exactly the floor the signer holds a key to, read from the one place that states it
        var size = keySize ?? (KeySizeFloors.MinimumHmacKeyBits(algorithm)
            ?? throw new ArgumentException($"Unsupported HMAC algorithm: {algorithm}", nameof(algorithm))) >> 3;

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
