// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com


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
