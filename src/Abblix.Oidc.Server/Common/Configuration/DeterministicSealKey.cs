// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// What a key configured for a deterministic seal (<see cref="Abblix.Jwt.Encryption.DeterministicAeadEncryptor"/>)
/// must be, and the hashes its HKDF key derivation can use: the one rule every setting keying such a seal is judged
/// by, the pairwise salt and the client secret encryption key among them.
/// </summary>
internal static class DeterministicSealKey
{
    /// <summary>
    /// The minimum decoded length of the key. It is the sole key material of the seal, so it carries 256 bits of
    /// secret entropy - anything shorter weakens every value the seal produces.
    /// </summary>
    private const int MinKeyBytes = 32;

    /// <summary>
    /// The hashes the HKDF key derivation of the seal can use.
    /// </summary>
    private static readonly HashAlgorithmName[] SupportedHashAlgorithms =
        [HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512];

    /// <summary>The hash <paramref name="name"/> names, or null when it names none the seal can use.</summary>
    /// <param name="name">The name a deployment configured.</param>
    public static HashAlgorithmName? HashAlgorithmNamed(string? name)
        => SupportedHashAlgorithms
            .Where(algorithm => algorithm.Name == name)
            .Select(algorithm => (HashAlgorithmName?)algorithm)
            .FirstOrDefault();

    /// <summary>Why this hash cannot key the seal, or null when it can.</summary>
    /// <param name="name">The name a deployment configured.</param>
    /// <param name="setting">How the refusal names the setting, such as "pairwise HashAlgorithm".</param>
    /// <param name="seal">How the refusal names the seal, such as "pairwise seal".</param>
    public static string? HashAlgorithmRefusal(string? name, string setting, string seal)
    {
        if (HashAlgorithmNamed(name) is not null)
            return null;

        var supported = string.Join(", ", SupportedHashAlgorithms.Select(algorithm => algorithm.Name));
        if (string.IsNullOrWhiteSpace(name))
            return $"The {setting} has no value: name one of {supported}.";

        return $"The {setting} '{name}' is not one the {seal} can use: {supported}.";
    }

    /// <summary>Why this key cannot key the seal, or null when it can.</summary>
    /// <param name="key">The base64 value a deployment configured.</param>
    /// <param name="setting">How the refusal names the setting, such as "pairwise salt".</param>
    /// <param name="seal">How the refusal names the seal, such as "pairwise subject seal".</param>
    public static string? KeyRefusal(string? key, string setting, string seal)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return $"The {setting} is required: it is the key material of the {seal}.";
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(key);
        }
        catch (FormatException)
        {
            return $"The {setting} must be a base64-encoded value.";
        }

        return decoded.Length < MinKeyBytes
            ? $"The {setting} must decode to at least {MinKeyBytes} bytes (256 bits) to key the "
                + $"{seal} securely, but it decoded to {decoded.Length} bytes."
            : null;
    }
}
