// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The Concat KDF (NIST SP 800-56A section 5.8.1) with SHA-256, as RFC 7518 section 4.6.2 applies it to ECDH-ES. It is
/// expressed over a raw shared secret <c>Z</c> so that a single implementation serves both the in-process
/// agreement (which materialises <c>Z</c> locally via <see cref="ECDiffieHellman.DeriveRawSecretAgreement"/>)
/// and the external-custodian path (where an HSM/KMS performs the agreement and returns <c>Z</c>). The
/// only step that needs the private key is the agreement; the KDF itself is public math and lives here.
/// </summary>
internal static class ConcatKeyDerivation
{
    /// <summary>
    /// Derives a key of <paramref name="keySizeInBytes"/> bytes from the shared secret
    /// <paramref name="sharedSecretZ"/>: each round is <c>SHA256(counter || Z || OtherInfo)</c> with a
    /// 32-bit big-endian round counter starting at 1, per SP 800-56A section 5.8.1. Rounds beyond the first cover
    /// a derived key longer than one hash output (for example a 512-bit CEK for A256CBC-HS512 under Direct
    /// Key Agreement).
    /// </summary>
    /// <param name="sharedSecretZ">The raw ECDH shared secret - the value NIST SP 800-56A and RFC 7518
    /// section 4.6 name <c>Z</c> (the agreement's field-sized X-coordinate). The <c>Z</c> suffix keeps the code
    /// symbol aligned with the specification the KDF transcribes.</param>
    /// <param name="algorithmId">The KDF AlgorithmID: the <c>enc</c> value in Direct Key Agreement mode,
    /// the <c>alg</c> value in the key-wrapping variants, per RFC 7518 section 4.6.2.</param>
    /// <param name="apu">The base64url <c>apu</c> (PartyUInfo) header value, or null when absent.</param>
    /// <param name="apv">The base64url <c>apv</c> (PartyVInfo) header value, or null when absent.</param>
    /// <param name="keySizeInBytes">The number of key bytes to derive.</param>
    /// <returns>The derived key.</returns>
    public static byte[] DeriveKey(
        byte[] sharedSecretZ,
        string algorithmId,
        string? apu,
        string? apv,
        int keySizeInBytes)
    {
        var otherInfo = BuildOtherInfo(algorithmId, apu, apv, keySizeInBytes);

        // Each round hashes (counter || Z || OtherInfo) per SP 800-56A section 5.8.1. The buffer is assembled
        // once and only the leading 4-byte counter is rewritten per round, so Z (the shared secret) and
        // OtherInfo are laid out after it.
        var roundInput = new byte[sizeof(uint) + sharedSecretZ.Length + otherInfo.Length];
        sharedSecretZ.CopyTo(roundInput.AsSpan(sizeof(uint)));
        otherInfo.CopyTo(roundInput.AsSpan(sizeof(uint) + sharedSecretZ.Length));

        var derivedKey = new byte[keySizeInBytes];
        Span<byte> round = stackalloc byte[SHA256.HashSizeInBytes];

        for (var offset = 0; offset < keySizeInBytes; offset += SHA256.HashSizeInBytes)
        {
            BinaryPrimitives.WriteUInt32BigEndian(roundInput, (uint)(offset / SHA256.HashSizeInBytes) + 1);

            SHA256.HashData(roundInput, round);
            round[..Math.Min(round.Length, keySizeInBytes - offset)].CopyTo(derivedKey.AsSpan(offset));
        }

        CryptographicOperations.ZeroMemory(roundInput.AsSpan(sizeof(uint), sharedSecretZ.Length));
        return derivedKey;
    }

    /// <summary>
    /// Builds the Concat KDF OtherInfo per RFC 7518 section 4.6.2:
    /// AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo, where the first three are 32-bit
    /// big-endian length-prefixed octet strings (the ASCII algorithm identifier and the base64url-decoded
    /// <c>apu</c>/<c>apv</c> values, empty when absent) and SuppPubInfo is the derived key length in bits
    /// as a 32-bit big-endian integer. SuppPrivInfo is the empty octet sequence.
    /// </summary>
    private static byte[] BuildOtherInfo(string algorithmId, string? apu, string? apv, int keySizeInBytes)
    {
        var algorithmIdBytes = Encoding.ASCII.GetBytes(algorithmId);
        var partyUInfo = apu != null ? Base64Url.DecodeFromChars(apu) : [];
        var partyVInfo = apv != null ? Base64Url.DecodeFromChars(apv) : [];

        var otherInfo = new byte[
            sizeof(uint) + algorithmIdBytes.Length +
            sizeof(uint) + partyUInfo.Length +
            sizeof(uint) + partyVInfo.Length +
            sizeof(uint)];

        var span = otherInfo.AsSpan()
            .WriteLengthPrefixed(algorithmIdBytes)
            .WriteLengthPrefixed(partyUInfo)
            .WriteLengthPrefixed(partyVInfo);

        BinaryPrimitives.WriteUInt32BigEndian(span, (uint)keySizeInBytes * 8);

        return otherInfo;
    }

    private static Span<byte> WriteLengthPrefixed(this Span<byte> destination, byte[] data)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination, (uint)data.Length);
        data.CopyTo(destination[sizeof(uint)..]);
        return destination[(sizeof(uint) + data.Length)..];
    }
}
