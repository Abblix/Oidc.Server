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

using System.Security.Cryptography;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Deterministic authenticated encryption bound to associated data: the same plaintext and associated data always
/// seal to the same bytes, different inputs seal to unrelated bytes, and tampering or a wrong associated data is
/// rejected on opening. This is the property a reversible, stable pseudonym needs - a value that is opaque and
/// unlinkable to outsiders yet recoverable by the holder of the key, and identical across sessions and hosts for the
/// same input.
/// </summary>
/// <remarks>
/// The encryption is AES Key Wrap with Padding (RFC 5649 / NIST SP 800-38F KWP) via <see cref="AesKeyWrapPadded"/>,
/// a standardised deterministic authenticated encryption whose integrity check rejects any tampered value on
/// unwrap. RFC 5649 has no associated-data input, so the associated data is bound into the key instead: a distinct
/// key encryption key is derived per associated-data value by HKDF, so a value sealed for one context cannot be
/// opened under another - its integrity check fails. The supplied key is the sole secret; HKDF expands it, mixing
/// the associated data into the context label, into a 256-bit key encryption key.
/// </remarks>
public sealed class DeterministicAeadEncryptor
{
    // AES-256 key encryption key derived per associated-data value.
    private const int KeyEncryptionKeySize = 32;

    // Domain-separation label for the HKDF context, keeping keys derived here unrelated to any other use of the
    // same secret; the associated data is appended to it to bind the key to its context.
    private static readonly byte[] ContextLabel = "Abblix.DeterministicAead.kwp"u8.ToArray();

    /// <summary>
    /// Creates an encryptor whose per-context key encryption keys are derived from <paramref name="key"/> by HKDF.
    /// </summary>
    /// <param name="hashAlgorithm">The hash used for the HKDF key derivation. Defaults to SHA-256 at the call sites;
    /// a caller honouring host-configured pairwise settings passes their chosen algorithm.</param>
    /// <param name="key">The key material. Its secrecy is the whole security of the seal.</param>
    public DeterministicAeadEncryptor(HashAlgorithmName hashAlgorithm, byte[] key)
    {
        _hashAlgorithm = hashAlgorithm;
        _key = key;
    }

    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly byte[] _key;

    /// <summary>
    /// Seals <paramref name="plaintext"/> bound to <paramref name="associatedData"/>. Deterministic: the same
    /// inputs always return the same bytes.
    /// </summary>
    public byte[] Seal(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
        => AesKeyWrapPadded.Wrap(DeriveKeyEncryptionKey(associatedData), plaintext);

    /// <summary>
    /// Opens a value produced by <see cref="Seal"/> under the same <paramref name="associatedData"/>.
    /// </summary>
    /// <returns>The recovered plaintext, or <c>null</c> when the value is malformed, tampered, or bound to
    /// different associated data.</returns>
    public byte[]? Open(ReadOnlySpan<byte> sealedData, ReadOnlySpan<byte> associatedData)
        => AesKeyWrapPadded.TryUnwrap(DeriveKeyEncryptionKey(associatedData), sealedData.ToArray(), out var plaintext)
            ? plaintext
            : null;

    private byte[] DeriveKeyEncryptionKey(ReadOnlySpan<byte> associatedData)
    {
        var info = new byte[ContextLabel.Length + associatedData.Length];
        ContextLabel.CopyTo(info, 0);
        associatedData.CopyTo(info.AsSpan(ContextLabel.Length));
        return HKDF.DeriveKey(_hashAlgorithm, _key, KeyEncryptionKeySize, salt: null, info);
    }
}
