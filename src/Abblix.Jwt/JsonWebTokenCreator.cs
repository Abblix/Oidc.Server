// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Responsible for creating JSON Web Tokens (JWTs). This class provides functionality to issue JWTs based on given claims and keys.
/// </summary>
/// <remarks>
/// The class uses custom signing and encryption implementations to create JWTs.
/// It supports setting standard claims such as issuer, audience, and times, as well as custom claims
/// contained within the provided <see cref="JsonWebToken"/> instance.
/// </remarks>
/// <param name="issuer">Signs a token and encrypts it when asked.</param>
/// <param name="signingAlgorithmsProvider">The provider for supported signing algorithms.</param>
/// <param name="encryptionAlgorithmsProvider">The provider for supported JWE key-management algorithms.</param>
internal sealed class JsonWebTokenCreator(
    NestedJwtIssuer issuer,
    SigningAlgorithmsProvider signingAlgorithmsProvider,
    EncryptionAlgorithmsProvider encryptionAlgorithmsProvider) : IJsonWebTokenCreator
{
    /// <summary>
    /// Gets the collection of signing algorithms supported for JWT creation.
    /// Dynamically determined from registered signers in the dependency injection container.
    /// </summary>
    public IEnumerable<string> SignedResponseAlgorithmsSupported => signingAlgorithmsProvider.Algorithms;

    /// <summary>
    /// Gets the collection of JWE key-management algorithms supported for encrypting a JWT on creation.
    /// Dynamically determined from the registered encryptors in the dependency injection container.
    /// </summary>
    public IEnumerable<string> EncryptedResponseAlgorithmsSupported => encryptionAlgorithmsProvider.KeyManagementAlgorithms;

    /// <summary>
    /// Asynchronously issues a JWT based on the specified JsonWebToken, signing key, and optional encryption key.
    /// </summary>
    /// <param name="token">The JsonWebToken object containing the payload of the JWT.</param>
    /// <param name="signingKey">The signing key as a JsonWebKey to sign the JWT.</param>
    /// <param name="encryptionKey">Optional encryption key as a JsonWebKey to encrypt the JWT.</param>
    /// <param name="keyEncryptionAlgorithm">
    /// JWE key management algorithm ("alg") that protects the Content Encryption Key with the
    /// recipient's key (RFC 7518 Section 4). Defaults to <c>RSA-OAEP-256</c>.
    /// Supported values are listed on <see cref="EncryptionAlgorithms.KeyManagement"/>;
    /// only used when <paramref name="encryptionKey"/> is provided.
    /// </param>
    /// <param name="contentEncryptionAlgorithm">
    /// JWE content encryption algorithm ("enc") that encrypts the payload with the CEK
    /// (RFC 7518 Section 5). Defaults to <c>A256CBC-HS512</c>.
    /// Supported values are listed on <see cref="EncryptionAlgorithms.ContentEncryption"/>;
    /// only used when <paramref name="encryptionKey"/> is provided.
    /// </param>
    /// <returns>A task that returns the JWT as a string.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the specified date time values cause an overflow.</exception>
    /// <remarks>
    /// The method creates a JWT using custom implementation that supports multiple audiences.
    /// Supports both JWS (signed) and JWE (encrypted) tokens.
    /// </remarks>
    public Task<string> IssueAsync(
        JsonWebToken token,
        JsonWebKey? signingKey,
        JsonWebKey? encryptionKey = null,
        string keyEncryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
        string contentEncryptionAlgorithm = EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)
        => issuer.IssueAsync(token, signingKey, encryptionKey, keyEncryptionAlgorithm, contentEncryptionAlgorithm);
}
