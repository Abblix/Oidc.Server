// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// What an in-process key ring mints, and how often.
/// </summary>
/// <remarks>
/// The counterpart of <see cref="MintedKeys"/> for a ring with no custodian behind it. It names no
/// key-encryption key because there is nothing to seal to and nothing to seal for: the keys never leave the
/// process that made them.
/// </remarks>
public sealed record LocalKeys
{
    /// <summary>The JWS algorithm the minted signing keys use, which also decides what is generated.</summary>
    public string SigningAlgorithm { get; init; } = SigningAlgorithms.RS256;

    /// <summary>
    /// The JWE key-management algorithm the minted encryption key uses, or null to mint no encryption key.
    /// </summary>
    public string? EncryptionAlgorithm { get; init; }

    /// <summary>The modulus size of a minted RSA key.</summary>
    public int RsaKeySize { get; init; } = 2048;

    /// <summary>How often a fresh key is minted and the previous one steps back from producing.</summary>
    public TimeSpan RotateEvery { get; init; } = TimeSpan.FromDays(30);

    /// <summary>
    /// How long a key that has stopped producing is still offered, so what it produced stays verifiable.
    /// </summary>
    /// <remarks>
    /// Must outlast the longest thing the key signed or encrypted. Retire a key sooner than the tokens it
    /// signed, and those tokens fail verification while their holders still believe them valid.
    /// </remarks>
    public TimeSpan KeepRetiredFor { get; init; } = TimeSpan.FromDays(7);
}
