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

using Abblix.Jwt;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The policy for the tier where the server mints its own keys and the custodian only protects them
/// (<c>UseKeysInProcess</c>): it generates them, encrypts them to the custodian's key-encryption key, keeps the
/// ciphertext in a shared ring, and rotates on schedule. No key names here - the server names what it creates.
/// </summary>
/// <remarks>
/// This is the weaker of the two postures, and naming it at the call site is the point: the private half is
/// unwrapped into process memory and stays there, so a compromised process yields the key itself rather than the
/// ability to ask the custodian to sign while its credential lives. In exchange, signing runs in process, and the
/// custodian is touched once per key rather than once per token. Choose <see cref="CustodianHeldKeys"/> when the
/// key must never be in memory at all.
/// </remarks>
public sealed record MintedKeys
{
    /// <summary>
    /// The custodian's name for the key-encryption key. Its versions seal and open the ring's entries, and it is
    /// the only key the custodian holds for this tier.
    /// </summary>
    /// <remarks>
    /// It must be an ASYMMETRIC key. Sealing uses its public half in process, which is what keeps the wrap local
    /// and needs no custodian round-trip; a symmetric KEK has no public half and would require one. Both Vault
    /// Transit and Azure Key Vault provision RSA keys, so this costs nothing in practice.
    /// </remarks>
    public required string KeyEncryptionKeyName { get; init; }

    /// <summary>The JWS algorithm the minted signing keys use, which also decides what is generated.</summary>
    public string SigningAlgorithm { get; init; } = SigningAlgorithms.RS256;

    /// <summary>
    /// The JWE key-management algorithm the minted encryption key uses, or null to mint no encryption key at all.
    /// </summary>
    /// <remarks>
    /// Name it when anything encrypts to this provider: it covers both the provider's own encrypted tokens and
    /// inbound JWE a client sent, such as an encrypted request object.
    /// </remarks>
    public string? EncryptionAlgorithm { get; init; }

    /// <summary>The modulus size for a minted RSA key. Ignored when the algorithm asks for an elliptic curve.</summary>
    public int RsaKeySize { get; init; } = 2048;

    /// <summary>
    /// How often a fresh key is minted. It sets the rotation grid: every pod derives the same period, and exactly
    /// one of them wins the insert for it.
    /// </summary>
    /// <remarks>
    /// A new key does not sign the moment it appears. It is published and verifiable for
    /// <c>KeyRingOptions.KeyRolloverPropagation</c> first, so a client whose JWKS cache is stale never meets a token
    /// signed by a key it lacks. Keep this comfortably larger than that window.
    /// </remarks>
    public TimeSpan RotateEvery { get; init; } = TimeSpan.FromDays(30);

    /// <summary>
    /// How long a key is kept after it stops signing, before it leaves the ring. Null keeps it for one full
    /// rotation period, which is the safe reading of <see cref="RotateEvery"/>.
    /// </summary>
    /// <remarks>
    /// This must outlast every token the key signed. Removing it early does not degrade anything gracefully: the
    /// key vanishes from <c>/jwks</c> and every unexpired token it signed stops verifying, which is why the
    /// default errs long rather than short. Set it explicitly only to say "no token of mine lives longer than
    /// this", and remember refresh tokens are signed too, not just access tokens.
    /// </remarks>
    public TimeSpan? KeepRetiredFor { get; init; }

    /// <summary>The JWE <c>alg</c> sealing an entry: how its data-encryption key is wrapped under the KEK.</summary>
    public string KeyWrapAlgorithm { get; init; } = EncryptionAlgorithms.KeyManagement.RsaOaep256;

    /// <summary>The JWE <c>enc</c> sealing an entry: how the key itself is encrypted.</summary>
    public string ContentEncryptionAlgorithm { get; init; } = EncryptionAlgorithms.ContentEncryption.Aes256Gcm;
}
