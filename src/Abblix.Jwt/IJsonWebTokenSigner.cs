// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Defines the contract for JSON Web Signature (JWS) signing and verification services.
/// </summary>
/// <remarks>
/// Part of the public JWT crypto surface alongside <see cref="IJsonWebTokenCreator"/> and
/// <see cref="IJsonWebTokenValidator"/>. Signing is asynchronous and cancellable so the private-key
/// operation can be served by an external key custodian (HSM/KMS/vault) over a network round-trip;
/// the in-process path completes synchronously inside the task.
/// </remarks>
public interface IJsonWebTokenSigner
{
    /// <summary>
    /// Creates a signed JSON Web Signature (JWS) token.
    /// </summary>
    /// <param name="token">The JSON Web Token to sign.</param>
    /// <param name="signingKey">The signing key, or null for an unsigned ("alg": "none") token.</param>
    /// <param name="cancellationToken">Cancels a network-backed external signing round-trip.</param>
    /// <returns>The JWS compact serialization string.</returns>
    Task<string> SignAsync(
        JsonWebToken token,
        JsonWebKey? signingKey,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the signature of a signed JWT.
    /// </summary>
    /// <param name="jwt">The base64url-encoded JWT string parts (header, payload, signature).</param>
    /// <param name="header">The JWT header.</param>
    /// <param name="signingKeys">The signing keys to try for verification.</param>
    /// <param name="cancellationToken">Cancels enumeration of the signing-key source.</param>
    /// <returns>A validation error if the signature is invalid; otherwise, null.</returns>
    Task<JwtValidationError?> ValidateAsync(
        string[] jwt,
        JsonWebTokenHeader header,
        IAsyncEnumerable<JsonWebKey> signingKeys,
        CancellationToken cancellationToken = default);
}
