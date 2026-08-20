// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.Signing;

/// <summary>
/// A signing backend that owns a slice of the server's signing keys and produces JWS signature bytes for the
/// keys it owns. Backends compose as peers behind <see cref="CompositeSigner"/>, which asks each in turn
/// whether it owns the key (<see cref="CanSign"/>) and routes to the first that does: the in-process
/// <see cref="LocalKeySigner"/> owns keys that carry private material, an external custodian backend
/// (<see cref="ExternalKeys.ExternalKeySigner"/>) owns the public-only keys whose <c>kid</c> is its handle. This is the
/// byte-level counterpart of the token-level <see cref="IJsonWebTokenSigner"/>: it works with bytes, not a
/// whole token, so an HSM/KMS/vault integration is one more backend and never touches JWS framing.
/// </summary>
public interface IDataSigner
{
    /// <summary>
    /// Reports whether this signer owns <paramref name="key"/> and can therefore sign with it. Ownership is a
    /// property of the key, not of the algorithm: the in-process backend owns keys that carry private material,
    /// an external custodian backend owns the public-only keys whose <c>kid</c> is one of its handles.
    /// </summary>
    /// <param name="key">The signing key the composite is about to route.</param>
    /// <returns><c>true</c> if this signer can sign with <paramref name="key"/>; otherwise <c>false</c>.</returns>
    bool CanSign(JsonWebKey key);

    /// <summary>
    /// Produces the signature bytes for <paramref name="data"/> under <paramref name="algorithm"/> using
    /// <paramref name="key"/>, in the JWS wire format for the algorithm.
    /// </summary>
    /// <param name="key">The signing key. Its <c>kid</c> is the custodian's handle when it is external.</param>
    /// <param name="algorithm">The JWS algorithm identifier (e.g. RS256, ES256) the signature must use.</param>
    /// <param name="data">The signing input bytes, BASE64URL(header) + '.' + BASE64URL(payload).</param>
    /// <param name="cancellationToken">Cancels the signing operation, including a custodian round-trip.</param>
    /// <returns>The raw signature bytes in JWS wire format for the algorithm.</returns>
    Task<byte[]> SignAsync(
        JsonWebKey key,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken);
}
