// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Opens an inbound JWE with the first candidate key that recovers its content.
/// </summary>
/// <param name="log">Records an inbound JWE that no key opened.</param>
/// <param name="serviceProvider">Resolves the content encryption algorithm by its 'enc' name.</param>
/// <param name="keyAttempt">Opens the token with one candidate key.</param>
internal sealed class JweDecryption(
    JweDecryptionLog log,
    IServiceProvider serviceProvider,
    JweKeyAttempt keyAttempt)
{
    /// <summary>
    /// Validates and decrypts JWE tokens using decoded byte parts and original string parts.
    /// Implements RFC 7516 (JWE) decryption.
    /// </summary>
    /// <remarks>
    /// A Chain of Responsibility over the RFC 7516 section 5.2 steps: decoding, reading the protected header,
    /// then decrypting. Each link either refuses the token with its error or hands it to the next one.
    /// </remarks>
    public async Task<Result<byte[], JwtValidationError>> DecryptAsync(
        string[] jwtParts,
        IAsyncEnumerable<JsonWebKey> decryptionKeys,
        CancellationToken cancellationToken = default)
        => await JweEnvelope.Read(jwtParts)
            .BindAsync(envelope => DecryptContentAsync(envelope, decryptionKeys, cancellationToken));

    private async Task<Result<byte[], JwtValidationError>> DecryptContentAsync(
        JweEnvelope envelope,
        IAsyncEnumerable<JsonWebKey> decryptionKeys,
        CancellationToken cancellationToken)
    {
        var keyId = envelope.Header.KeyId;

        // Per RFC 7517 Section 4.4, 'alg' parameter in JWK is OPTIONAL
        // Filter only by kid when present - algorithm compatibility is validated during decryption attempt
        if (keyId.HasValue())
            decryptionKeys = decryptionKeys.Where(key => string.Equals(key.KeyId, keyId, StringComparison.Ordinal));

        // Resolve the content decryptor by 'enc'. The registered set is the allow-list of content
        // encryption algorithms for incoming JWE - an unregistered 'enc' yields no decryptor and is
        // rejected outright.
        var contentDecryptor = serviceProvider
            .GetKeyedService<IContentEncryptionAlgorithm>(envelope.EncryptionAlgorithm);
        if (contentDecryptor == null)
            return new JwtValidationError(JwtError.InvalidToken, "Unsupported 'enc' content encryption algorithm in JWE");

        var keysTried = 0;
        await foreach (var key in decryptionKeys.WithCancellation(cancellationToken))
        {
            keysTried++;

            if (await keyAttempt.TryOpenAsync(envelope, contentDecryptor, key, cancellationToken) is { } plaintext)
                return plaintext;
        }

        // Logged once, after every key, so the record says nothing about which key failed or why: the sender's
        // answer stays the same whatever the cause, as RFC 7516 section 11.5 requires.
        if (keysTried == 0)
        {
            log.NoDecryptionKey(envelope);
            return new JwtValidationError(JwtError.InvalidToken, "No decryption keys found");
        }

        log.NoKeyOpened(envelope, keysTried);
        return new JwtValidationError(JwtError.InvalidToken, "Failed to decrypt JWE with any available key");
    }
}
