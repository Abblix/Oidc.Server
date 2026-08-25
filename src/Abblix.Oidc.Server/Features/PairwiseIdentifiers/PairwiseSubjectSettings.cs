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
    private const int MinSaltBytes = 32;

    /// <summary>
    /// A base64-encoded cryptographic key that keys the deterministic authenticated-encryption seal producing
    /// pairwise identifiers. This value MUST be kept secret, generated once, and never changed
    /// (changing it would invalidate all existing pairwise identifiers - none could be opened back).
    /// Minimum length: 32 bytes (256 bits) before encoding.
    /// </summary>
    /// <exception cref="ArgumentException">The salt is missing, is not valid base64, or decodes to fewer than
    /// 32 bytes.</exception>
    /// <remarks>
    /// Judged by whoever wires it rather than on assignment: settings the host bound are judged when the host
    /// starts, by <see cref="PairwiseSubjectSettingsValidator"/>, and an instance handed to
    /// <c>AddPairwiseSubjectIdentifiers</c> is judged there. Refusing in the accessor would sound stricter and
    /// be worse - the configuration binder assigns properties by reflection, so the refusal would reach the
    /// host wrapped in a <c>TargetInvocationException</c> naming reflection instead of the setting, and it
    /// would fire before any validator could say which rule failed.
    /// </remarks>
    public required string Salt { get; init; }

    /// <summary>
    /// The hash algorithm used for the HKDF key derivation that keys the pairwise seal. Defaults to SHA-256.
    /// Supported algorithms: SHA256, SHA384, SHA512, SHA1.
    /// </summary>
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;

    /// <summary>Refuses a salt that cannot key the seal.</summary>
    /// <param name="salt">The base64 value a deployment configured.</param>
    /// <exception cref="ArgumentException">It is missing, is not valid base64, or decodes to fewer than 32 bytes.</exception>
    /// <remarks>
    /// Reachable because the property cannot be the only judge. The configuration binder constructs the
    /// object and then sets only the properties whose keys are present, so an absent key never enters the
    /// accessor - <c>required</c> is a compiler rule and the binder does not enforce it. A caller holding an
    /// instance it did not write asks here instead.
    /// </remarks>
    public static void ValidateSalt(string? salt)
    {
        if (SaltRefusal(salt) is { } refusal)
        {
            throw new ArgumentException(refusal, nameof(salt));
        }
    }

    /// <summary>Why this salt cannot key the seal, or null when it can.</summary>
    /// <param name="salt">The base64 value a deployment configured.</param>
    /// <remarks>
    /// Returned rather than thrown, so one rule serves both callers: whoever HOLDS the value throws on it,
    /// and whoever REPORTS on it - a startup options validator - hands the same sentence to the host. Two
    /// shapes of one rule cannot disagree; two rules would.
    /// </remarks>
    public static string? SaltRefusal(string? salt)
    {
        if (string.IsNullOrWhiteSpace(salt))
        {
            return "The pairwise salt is required: it is the key material of the pairwise subject seal.";
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(salt);
        }
        catch (FormatException)
        {
            return "The pairwise salt must be a base64-encoded value.";
        }

        return decoded.Length < MinSaltBytes
            ? $"The pairwise salt must decode to at least {MinSaltBytes} bytes (256 bits) to key the "
                + $"pairwise subject seal securely, but it decoded to {decoded.Length} bytes."
            : null;
    }
}
