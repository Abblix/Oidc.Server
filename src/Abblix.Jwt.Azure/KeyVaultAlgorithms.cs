// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Frozen;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace Abblix.Jwt.Azure;

/// <summary>
/// Names each JOSE algorithm the way the Azure Key Vault SDK does; an algorithm absent here is one the vault is
/// not asked to perform.
/// </summary>
internal static class KeyVaultAlgorithms
{
    private static readonly FrozenDictionary<string, SignatureAlgorithm> SignatureAlgorithms =
        new Dictionary<string, SignatureAlgorithm>
        {
            [SigningAlgorithms.RS256] = SignatureAlgorithm.RS256,
            [SigningAlgorithms.RS384] = SignatureAlgorithm.RS384,
            [SigningAlgorithms.RS512] = SignatureAlgorithm.RS512,

            [SigningAlgorithms.PS256] = SignatureAlgorithm.PS256,
            [SigningAlgorithms.PS384] = SignatureAlgorithm.PS384,
            [SigningAlgorithms.PS512] = SignatureAlgorithm.PS512,

            [SigningAlgorithms.ES256] = SignatureAlgorithm.ES256,
            [SigningAlgorithms.ES384] = SignatureAlgorithm.ES384,
            [SigningAlgorithms.ES512] = SignatureAlgorithm.ES512,
        }.ToFrozenDictionary(StringComparer.Ordinal);

    private static readonly FrozenDictionary<string, EncryptionAlgorithm> KeyUnwrapAlgorithms =
        new Dictionary<string, EncryptionAlgorithm>
        {
            [EncryptionAlgorithms.KeyManagement.RsaOaep256] = EncryptionAlgorithm.RsaOaep256,
            [EncryptionAlgorithms.KeyManagement.RsaOaep] = EncryptionAlgorithm.RsaOaep,
            [EncryptionAlgorithms.KeyManagement.Rsa1_5] = EncryptionAlgorithm.Rsa15,
        }.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>The SDK's name for the JWS <paramref name="algorithm"/>.</summary>
    /// <exception cref="NotSupportedException">The vault is not asked to sign under this algorithm.</exception>
    public static SignatureAlgorithm ForSigning(string algorithm)
        => SignatureAlgorithms.TryGetValue(algorithm, out var signatureAlgorithm)
            ? signatureAlgorithm
            : throw new NotSupportedException($"The Azure Key Vault store does not sign '{algorithm}'.");

    /// <summary>The SDK's name for the JWE key-management <paramref name="algorithm"/>.</summary>
    /// <exception cref="NotSupportedException">The vault is not asked to unwrap under this algorithm.</exception>
    public static EncryptionAlgorithm ForUnwrapping(string algorithm)
        => KeyUnwrapAlgorithms.TryGetValue(algorithm, out var encryptionAlgorithm)
            ? encryptionAlgorithm
            : throw new NotSupportedException($"The Azure Key Vault store does not unwrap '{algorithm}'.");
}
