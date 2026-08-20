// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;

namespace Abblix.Jwt.Vault;

/// <summary>
/// The body of a KV v2 write, and the shape of what comes back out of a read.
/// </summary>
internal sealed record KeyValueRequest
{
    /// <summary>The write options, which for this store means only the check-and-set guard.</summary>
    [JsonPropertyName("options")]
    public required CheckAndSet Options { get; init; }

    /// <summary>The entry itself.</summary>
    [JsonPropertyName("data")]
    public required Entry Data { get; init; }

    /// <summary>
    /// KV v2's conditional-write guard, and the whole of the ring's coordination.
    /// </summary>
    internal sealed record CheckAndSet
    {
        /// <summary>
        /// The version the write expects to find. Zero means "this path has never existed", so the write creates
        /// or fails: exactly one pod minting a period can succeed, and no lock service is needed to decide which.
        /// </summary>
        [JsonPropertyName("cas")]
        public required int Cas { get; init; }
    }

    /// <summary>
    /// One ring entry as it sits in Vault. It is ciphertext and a timestamp: the store learns nothing about the
    /// key, and could not open it if it tried.
    /// </summary>
    internal sealed record Entry
    {
        /// <summary>The envelope: the private key, sealed to the custodian's key-encryption key.</summary>
        [JsonPropertyName("jwe")]
        public required string Jwe { get; init; }

        /// <summary>
        /// When the key was minted, round-trip formatted so it reads back identically regardless of culture.
        /// </summary>
        [JsonPropertyName("createdAt")]
        public required string CreatedAt { get; init; }
    }
}
