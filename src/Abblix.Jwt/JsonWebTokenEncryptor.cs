// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Encryption;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Handles encryption and decryption of JSON Web Encryption (JWE) tokens.
/// Implements RFC 7516 (JWE) encryption and decryption.
/// </summary>
/// <param name="encryption">Produces a JWE around an inner token.</param>
/// <param name="decryption">Opens an inbound JWE with the keys it is given.</param>
internal sealed class JsonWebTokenEncryptor(JweEncryption encryption, JweDecryption decryption) : IJsonWebTokenEncryptor
{
    /// <inheritdoc />
    public Task<string> EncryptAsync(
        byte[] plaintext,
        JsonWebKey encryptionKey,
        string? tokenType,
        string keyEncryptionAlgorithm,
        string contentEncryptionAlgorithm,
        CancellationToken cancellationToken = default)
        => encryption.EncryptAsync(
            plaintext, encryptionKey, tokenType, keyEncryptionAlgorithm, contentEncryptionAlgorithm, cancellationToken);

    /// <inheritdoc />
    public Task<Result<byte[], JwtValidationError>> DecryptAsync(
        string[] jwtParts,
        IAsyncEnumerable<JsonWebKey> decryptionKeys,
        CancellationToken cancellationToken = default)
        => decryption.DecryptAsync(jwtParts, decryptionKeys, cancellationToken);
}
