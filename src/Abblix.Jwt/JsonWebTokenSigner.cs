// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Handles signing and signature verification of JSON Web Signature (JWS) tokens.
/// </summary>
/// <remarks>
/// A Facade over <see cref="JwsTokenSigner"/>, which signs, and <see cref="JwsSignatureVerifier"/>, which verifies.
/// </remarks>
/// <param name="tokenSigner">Encodes a token and signs it.</param>
/// <param name="signatureVerifier">Checks a token's signature under the keys it may be signed with.</param>
internal sealed class JsonWebTokenSigner(JwsTokenSigner tokenSigner, JwsSignatureVerifier signatureVerifier)
    : IJsonWebTokenSigner
{
    /// <inheritdoc />
    public Task<string> SignAsync(
        JsonWebToken token,
        JsonWebKey? signingKey,
        CancellationToken cancellationToken = default)
        => tokenSigner.SignAsync(token, signingKey, cancellationToken);

    /// <inheritdoc />
    public Task<JwtValidationError?> ValidateAsync(
        string[] jwt,
        JsonWebTokenHeader header,
        IAsyncEnumerable<JsonWebKey> signingKeys,
        CancellationToken cancellationToken = default)
        => signatureVerifier.ValidateAsync(jwt, header, signingKeys, cancellationToken);
}
