// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// One candidate key's attempt at an inbound JWE: recover the Content Encryption Key with it, then open the content.
/// </summary>
/// <param name="contentKeyDecryptor">The key-recovery seam: it recovers the CEK in process for a key that carries its
/// private/secret material, or via an external key custodian for a public-only one. Only decryption routes
/// local-vs-custodian; encryption stays entirely in process and does not pass through this seam.</param>
internal sealed class JweKeyAttempt(IContentKeyDecryptor contentKeyDecryptor)
{
    /// <summary>
    /// Opens <paramref name="envelope"/> with <paramref name="key"/>.
    /// </summary>
    /// <returns>The plaintext, or null when this key does not open the token, whatever the reason.</returns>
    public async Task<byte[]?> TryOpenAsync(
        JweEnvelope envelope,
        IContentEncryptionAlgorithm contentDecryptor,
        JsonWebKey key,
        CancellationToken cancellationToken)
    {
        var encryptedKey = envelope.Parts[1];
        var iv = envelope.Parts[2];
        var ciphertext = envelope.Parts[3];
        var authTag = envelope.Parts[4];
        var aad = JweCompactSerialization.AdditionalAuthenticatedData(envelope.EncodedHeader);

        // The key-recovery seam recovers the CEK - in process for a key with secret material, or via the
        // external custodian for a public-only key - and returns null on any decryption failure, which the
        // mitigation below turns into a uniform outcome. The "must have the secret half" gate lives with the
        // seam's routing.

        // RFC 7516 section 11.5: substitute a randomly generated CEK of the correct size and still run the
        // AEAD step when CEK decryption fails - wrong key, malformed padding, or an unregistered
        // key-management 'alg' - OR when it succeeds with a structurally valid but wrong-length key.
        // The authentication tag then fails exactly as it would for a successful-but-wrong CEK, so a
        // decryption failure is processed identically regardless of its cause. The wrong-length case
        // matters because a content decryptor fast-fails on a length mismatch before doing the
        // AEAD/HMAC work, whereas a correct-length random CEK runs the full step - leaving that
        // difference in place would be an observable timing oracle signalling valid PKCS1 padding.
        // This is what makes RSA1_5 (RSAES-PKCS1-v1_5) safe to support: it closes the
        // Bleichenbacher/Manger padding oracle by removing the observable difference between valid
        // and invalid padding.
        var contentEncryptionKey = await contentKeyDecryptor.DecryptKeyAsync(
            envelope.Header, key, envelope.Algorithm, encryptedKey, cancellationToken);
        if (contentEncryptionKey == null || contentEncryptionKey.Length != contentDecryptor.KeySizeInBytes)
            contentEncryptionKey = CryptoRandom.GetRandomBytes(contentDecryptor.KeySizeInBytes);

        // Byte-oriented result: a JWS-wrapping caller (the validator) does the UTF-8 decode.
        return contentDecryptor.TryDecrypt(
            contentEncryptionKey,
            new EncryptedData(iv, ciphertext, authTag),
            aad,
            out var plaintext)
            ? plaintext
            : null;
    }
}
