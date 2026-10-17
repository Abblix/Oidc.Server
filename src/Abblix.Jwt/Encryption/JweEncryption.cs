// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Produces a JWE in compact serialization (RFC 7516 section 5.1) around an inner token.
/// </summary>
/// <param name="serviceProvider">Resolves the content encryption algorithm by its 'enc' name.</param>
/// <param name="localKeyEncryptor">Produces the Content Encryption Key and its wrapped form. Producing a JWE wraps
/// the key in process - with the recipient's public half for asymmetric algorithms, or a locally held shared secret
/// for symmetric ones - so encryption never needs a custodian.</param>
internal sealed class JweEncryption(IServiceProvider serviceProvider, LocalKeyEncryptor localKeyEncryptor)
{
    /// <summary>
    /// Encrypts an inner JWS token to create a JWE token.
    /// Implements RFC 7516 (JWE) encryption.
    /// </summary>
    public Task<string> EncryptAsync(
        byte[] plaintext,
        JsonWebKey encryptionKey,
        string? tokenType,
        string keyEncryptionAlgorithm,
        string contentEncryptionAlgorithm,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Resolve content encryptor to get required CEK size
        var contentEncryptor = serviceProvider.GetRequiredKeyedService<IContentEncryptionAlgorithm>(contentEncryptionAlgorithm);

        var header = new JsonWebTokenHeader(new JsonObject())
        {
            Algorithm = keyEncryptionAlgorithm,
            EncryptionAlgorithm = contentEncryptionAlgorithm,
            Type = tokenType,
            KeyId = encryptionKey.KeyId
        };

        // Produce the CEK and wrap it in process. Key-wrapping algorithms return a random CEK; "dir" returns the
        // shared key itself; ECDH-ES derives the CEK from the ephemeral-static agreement. Either step may add
        // algorithm parameters to the header ('epk' for ECDH-ES, 'iv'/'tag' for AES-GCM key wrap, 'p2s'/'p2c' for
        // PBES2).
        var (contentEncryptionKey, encryptedKey) = localKeyEncryptor.EncryptKey(
            header, encryptionKey, keyEncryptionAlgorithm, contentEncryptor.KeySizeInBytes);

        // Encode header AFTER key encryption (in case it was modified)
        var headerEncoded = JweCompactSerialization.EncodeHeader(header.Json);

        // AAD is the encoded JWE header
        var additionalAuthenticatedData = JweCompactSerialization.AdditionalAuthenticatedData(headerEncoded);

        var (iv, ciphertext, authTag) = contentEncryptor.Encrypt(
            contentEncryptionKey,
            plaintext,
            additionalAuthenticatedData);

        // JWE Compact Serialization: header.encryptedKey.iv.ciphertext.authTag
        return Task.FromResult(JweCompactSerialization.Encode(headerEncoded, encryptedKey, iv, ciphertext, authTag));
    }
}
