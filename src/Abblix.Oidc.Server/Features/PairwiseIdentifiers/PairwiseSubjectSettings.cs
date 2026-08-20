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
    /// A base64-encoded cryptographic key that keys the deterministic authenticated-encryption seal producing
    /// pairwise identifiers. This value MUST be kept secret, generated once, and never changed
    /// (changing it would invalidate all existing pairwise identifiers - none could be opened back).
    /// Minimum recommended length: 32 bytes (256 bits) before encoding.
    /// </summary>
    public required string Salt { get; init; }

    /// <summary>
    /// The hash algorithm used for the HKDF key derivation that keys the pairwise seal. Defaults to SHA-256.
    /// Supported algorithms: SHA256, SHA384, SHA512, SHA1.
    /// </summary>
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;
}
