// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// Configuration for pairwise subject identifier generation.
/// The salt is a server-side secret that keys the reversible pairwise seal, so that even with knowledge of the
/// user's real subject and the sector, an attacker cannot derive or open the pairwise identifier.
/// </summary>
public record PairwiseSubjectSettings
{
    /// <summary>
    /// The minimum decoded length of the salt. It is the sole key material of the pairwise seal, so it carries
    /// 256 bits of secret entropy - anything shorter weakens every pairwise identifier the server issues.
    /// </summary>
    public const int MinSaltBytes = 32;

    private readonly string _salt = null!;

    /// <summary>
    /// A base64-encoded cryptographic key that keys the deterministic authenticated-encryption seal producing
    /// pairwise identifiers. This value MUST be kept secret, generated once, and never changed
    /// (changing it would invalidate all existing pairwise identifiers - none could be opened back).
    /// Minimum length: <see cref="MinSaltBytes"/> bytes before encoding.
    /// </summary>
    /// <exception cref="ArgumentException">The salt is missing, is not valid base64, or decodes to fewer than
    /// <see cref="MinSaltBytes"/> bytes.</exception>
    /// <remarks>
    /// Judged by the value itself rather than by whoever hands it over, because more than one hand does.
    /// <c>AddPairwiseSubjectIdentifiers</c> takes an instance as an argument and registers it with
    /// <c>TryAddSingleton</c>, so a host that registered its own wins - and a check placed at the extension
    /// judges the copy nobody ends up using, which reads as a guarantee and is not one. Here there is no
    /// unvalidated instance to hold: configuration binding, an object initialiser and a <c>with</c> expression
    /// all run this, so a weak seal key fails where it is written.
    /// </remarks>
    public required string Salt
    {
        get => _salt;
        init => _salt = Validated(value);
    }

    /// <summary>
    /// The hash algorithm used for the HKDF key derivation that keys the pairwise seal. Defaults to SHA-256.
    /// Supported algorithms: SHA256, SHA384, SHA512, SHA1.
    /// </summary>
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

    private static string Validated(string salt)
    {
        if (string.IsNullOrWhiteSpace(salt))
            throw new ArgumentException(
                "The pairwise salt is required: it is the key material of the pairwise subject seal.",
                nameof(salt));

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(salt);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "The pairwise salt must be a base64-encoded value.", nameof(salt), exception);
        }

        if (decoded.Length < MinSaltBytes)
            throw new ArgumentException(
                $"The pairwise salt must decode to at least {MinSaltBytes} bytes (256 bits) to key the " +
                $"pairwise subject seal securely, but it decoded to {decoded.Length} bytes.",
                nameof(salt));

        return salt;
    }
}
