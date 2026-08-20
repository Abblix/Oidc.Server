// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Defines the contract for JSON Web Encryption (JWE) token encryption and decryption services.
/// </summary>
/// <remarks>
/// The payload is exchanged as bytes rather than a string: the CEK protects arbitrary octets, and a
/// later feature encrypts a binary (non-text) payload, so a byte contract fits every caller while a
/// JWS-wrapping caller does the trivial UTF-8 conversion. Encryption is asynchronous and cancellable so
/// key management (unwrap/agree) can be served by an external key custodian over a network round-trip;
/// the in-process path completes synchronously inside the task.
/// </remarks>
public interface IJsonWebTokenEncryptor
{
    /// <summary>
    /// Encrypts a plaintext payload (typically an inner JWS) into a JWE token.
    /// Implements RFC 7516 (JWE) encryption.
    /// </summary>
    /// <param name="plaintext">The bytes to encrypt; a JWS-wrapping caller UTF-8 encodes the inner JWS.</param>
    /// <param name="encryptionKey">The JSON Web Key to use for encryption.</param>
    /// <param name="tokenType">The token type to set in the JWE header.</param>
    /// <param name="keyEncryptionAlgorithm">The key encryption algorithm (e.g. RSA-OAEP-256).</param>
    /// <param name="contentEncryptionAlgorithm">The content encryption algorithm (e.g. A256CBC-HS512).</param>
    /// <param name="cancellationToken">Cancels a network-backed external key-management round-trip.</param>
    /// <returns>The JWE compact serialization string.</returns>
    Task<string> EncryptAsync(
        byte[] plaintext,
        JsonWebKey encryptionKey,
        string? tokenType,
        string keyEncryptionAlgorithm,
        string contentEncryptionAlgorithm,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates and decrypts a JWE token.
    /// Implements RFC 7516 (JWE) decryption.
    /// </summary>
    /// <param name="jwtParts">The base64url-encoded JWE string parts.</param>
    /// <param name="decryptionKeys">The decryption keys to try.</param>
    /// <param name="cancellationToken">Cancels enumeration of the decryption-key source and any external unwrap.</param>
    /// <returns>A result containing either the decrypted plaintext bytes or a validation error.</returns>
    Task<Result<byte[], JwtValidationError>> DecryptAsync(
        string[] jwtParts,
        IAsyncEnumerable<JsonWebKey> decryptionKeys,
        CancellationToken cancellationToken = default);
}
