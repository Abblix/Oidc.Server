// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Xunit;

namespace Abblix.Jwt.Azure.UnitTests;

/// <summary>
/// The SDK names each JOSE algorithm maps to. The tables behind <see cref="KeyVaultAlgorithms"/> are held
/// complete here: every recognized algorithm is either mapped to the SDK value of the same name or named below as
/// one the vault is not asked to perform, so an algorithm added to a catalog fails until somebody decides which.
/// </summary>
public class KeyVaultAlgorithmsTests
{
    private static readonly string[] AlgorithmsVaultDoesNotSign =
    [
        SigningAlgorithms.None,
        SigningAlgorithms.HS256,
        SigningAlgorithms.HS384,
        SigningAlgorithms.HS512,
    ];

    private static readonly string[] AlgorithmsVaultUnwraps =
    [
        EncryptionAlgorithms.KeyManagement.Rsa1_5,
        EncryptionAlgorithms.KeyManagement.RsaOaep,
        EncryptionAlgorithms.KeyManagement.RsaOaep256,
    ];

    public static TheoryData<string> SigningAlgorithmsRecognized => new(SigningAlgorithms.Known);

    public static TheoryData<string> KeyManagementAlgorithmsRecognized => new(
        typeof(EncryptionAlgorithms.KeyManagement)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(constant => constant.IsLiteral)
            .Select(constant => (string)constant.GetRawConstantValue()!));

    [Theory]
    [MemberData(nameof(SigningAlgorithmsRecognized))]
    public void EverySigningAlgorithm_IsMappedOrRefused(string algorithm)
    {
        if (AlgorithmsVaultDoesNotSign.Contains(algorithm))
            Assert.Throws<NotSupportedException>(() => KeyVaultAlgorithms.ForSigning(algorithm));
        else
            Assert.Equal(algorithm, KeyVaultAlgorithms.ForSigning(algorithm).ToString());
    }

    [Theory]
    [MemberData(nameof(KeyManagementAlgorithmsRecognized))]
    public void EveryKeyManagementAlgorithm_IsMappedOrRefused(string algorithm)
    {
        if (AlgorithmsVaultUnwraps.Contains(algorithm))
            Assert.Equal(algorithm, KeyVaultAlgorithms.ForUnwrapping(algorithm).ToString());
        else
            Assert.Throws<NotSupportedException>(() => KeyVaultAlgorithms.ForUnwrapping(algorithm));
    }
}
