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

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Deterministic authenticated encryption in the Synthetic IV (SIV) style: the same plaintext and associated data
/// always seal to the same bytes, while different inputs seal to unrelated bytes and tampering is rejected. This is
/// the property a reversible, stable pseudonym needs - a value that is opaque and unlinkable to outsiders yet
/// recoverable by the holder of the key, and identical across sessions for the same input.
/// </summary>
/// <remarks>
/// The construction follows RFC 5297 in shape but uses HMAC as the pseudorandom function instead of AES-CMAC
/// (which the BCL does not provide): a 128-bit synthetic IV is derived by HMAC over the associated data and
/// plaintext, then used as the AES-CTR counter to encrypt the plaintext; the sealed value is the IV followed by
/// the ciphertext. Because the IV is derived from the plaintext, it is stable per input and effectively unique per
/// distinct input. Unlike a fixed or truncated nonce fed to AES-GCM - where nonce reuse recovers the polynomial
/// authentication key and enables universal forgery - the failure mode here is far milder and never recovers a
/// key: two DISTINCT inputs would have to collide on the counter derived from the synthetic IV (birthday-bounded
/// around 2^63 seals, effectively unreachable for a pseudonym population), and such a collision merely reuses the
/// keystream, leaking the XOR of those two plaintexts. For identical inputs the same IV is the intended
/// deterministic behaviour. Opening recomputes the IV from the recovered plaintext and rejects in constant time on
/// mismatch, so any change to the IV or ciphertext, or a wrong associated data, fails to open. Two subkeys (a MAC
/// key and an encryption key) are derived from the supplied key by HKDF so the same bytes never both authenticate
/// and encrypt.
/// </remarks>
public sealed class DeterministicAeadEncryptor
{
    private const int IvSize = 16;
    private const int SubKeySize = 32;

    // HKDF context labels separating the MAC subkey from the encryption subkey.
    private static readonly byte[] MacInfo = "Abblix.DeterministicAead.hmac"u8.ToArray();
    private static readonly byte[] EncInfo = "Abblix.DeterministicAead.aes-ctr"u8.ToArray();

    /// <summary>
    /// Creates an encryptor whose MAC and encryption subkeys are derived from <paramref name="key"/> by HKDF-SHA256.
    /// </summary>
    /// <param name="hashAlgorithm">The hash used for both the HKDF key derivation and the HMAC synthetic-IV
    /// pseudorandom function; the same choice in both keeps the construction internally consistent. Defaults to
    /// SHA-256. A caller honouring host-configured pairwise settings passes their chosen algorithm.</param>
    /// <param name="key">The key material. Its secrecy is the whole security of the seal.</param>
    /// <param name="salt">Optional HKDF salt mixed into the subkey derivation. It need not be secret; its purpose
    /// is domain separation, so the same <paramref name="key"/> used in another context yields unrelated subkeys.
    /// A caller sealing pairwise identifiers passes the pairwise salt here, binding the seal to that context.</param>
    public DeterministicAeadEncryptor(HashAlgorithmName hashAlgorithm, byte[] key, byte[]? salt = null)
    {
        _hashAlgorithm = hashAlgorithm;
        _macKey = HKDF.DeriveKey(_hashAlgorithm, key, SubKeySize, salt, MacInfo);
        _encKey = HKDF.DeriveKey(_hashAlgorithm, key, SubKeySize, salt, EncInfo);
    }

    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly byte[] _macKey;
    private readonly byte[] _encKey;

    /// <summary>
    /// Seals <paramref name="plaintext"/> bound to <paramref name="associatedData"/>. Deterministic: the same
    /// inputs always return the same bytes.
    /// </summary>
    /// <returns>The synthetic IV followed by the ciphertext.</returns>
    public byte[] Seal(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        var iv = SyntheticIv(plaintext, associatedData);
        var ciphertext = plaintext.Transform(_encKey, CounterFrom(iv));

        var sealedData = new byte[IvSize + ciphertext.Length];
        iv.CopyTo(sealedData, 0);
        ciphertext.CopyTo(sealedData, IvSize);
        return sealedData;
    }

    /// <summary>
    /// Opens a value produced by <see cref="Seal"/> under the same <paramref name="associatedData"/>.
    /// </summary>
    /// <returns>The recovered plaintext, or <c>null</c> when the value is malformed, tampered, or bound to
    /// different associated data.</returns>
    public byte[]? Open(ReadOnlySpan<byte> sealedData, ReadOnlySpan<byte> associatedData)
    {
        if (sealedData.Length < IvSize)
            return null;

        var iv = sealedData[..IvSize].ToArray();
        var ciphertext = sealedData[IvSize..];
        var plaintext = ciphertext.Transform(_encKey, CounterFrom(iv));

        var expectedIv = SyntheticIv(plaintext, associatedData);
        return CryptographicOperations.FixedTimeEquals(iv, expectedIv) ? plaintext : null;
    }

    // The synthetic IV: HMAC over a length-prefixed encoding of the associated data followed by the plaintext, so
    // the boundary between the two is unambiguous (a byte moved from one to the other changes the IV). Truncated to
    // the 128-bit AES block size.
    private byte[] SyntheticIv(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        var input = new byte[sizeof(uint) + associatedData.Length + plaintext.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)associatedData.Length);
        associatedData.CopyTo(input.AsSpan(sizeof(uint)));
        plaintext.CopyTo(input.AsSpan(sizeof(uint) + associatedData.Length));

        using var hmac = IncrementalHash.CreateHMAC(_hashAlgorithm, _macKey);
        hmac.AppendData(input);
        return hmac.GetHashAndReset()[..IvSize];
    }

    // RFC 5297 §2.6: before using the synthetic IV as the CTR counter, clear the 31st and 63rd bits (from the
    // right) so the per-block counter increment never carries across those boundaries. The full IV is still what
    // authentication compares - only the counter derivation drops these two bits.
    private static byte[] CounterFrom(byte[] iv)
    {
        var counter = (byte[])iv.Clone();
        counter[8] &= 0x7F;
        counter[12] &= 0x7F;
        return counter;
    }
}
