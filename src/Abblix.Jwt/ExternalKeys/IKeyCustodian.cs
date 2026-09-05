// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Host-implemented custodian for the external private keys the library never holds in process: they live in an
/// HSM, a cloud KMS, or a vault transit engine, and only the private operations cross the boundary. A key
/// published public-only routes its private operation here by <c>kid</c>: SIGNING for a signing key, and for a
/// decryption key an RSA/symmetric UNWRAP or an ECDH-ES AGREEMENT. The public operations - signature
/// verification, and wrapping a CEK with the recipient's public half - stay in process and never reach the
/// custodian. Wire it with <c>AddCustodian</c> and a placement call; a host with no external keys leaves it
/// unregistered.
/// </summary>
/// <remarks>
/// Every private operation is addressed by <c>kid</c>, the custodian's handle for that exact key version,
/// identical to the published key's <c>kid</c> - there is no separate identifier and no mapping. The public
/// halves the library publishes come from <see cref="GetKeyVersionsAsync"/>, which enumerates a named key's
/// versions so a rotation can overlap. The implementation never receives or returns private key material, and
/// only needs to implement the private operations its own keys require: a signing-only custodian leaves unwrap
/// and agree unreachable, and a decryption-only custodian leaves sign unreachable. Direct encryption (<c>dir</c>)
/// and password-based key management (PBES2) have no external form - the CEK is the secret itself, or is derived
/// from it by a password KDF - so they are never routed here and fail closed. Every operation is a round-trip to
/// the custodian, so the contract returns <see cref="Task{TResult}"/> throughout.
/// </remarks>
public interface IKeyCustodian
{
    /// <summary>
    /// Signs <paramref name="data"/> with a signing key held by the custodian, returning the signature in the
    /// JWS wire format for <paramref name="algorithm"/>. Called for a signing key the library holds public-only.
    /// </summary>
    /// <param name="keyId">The custodian's handle for the signing key version.</param>
    /// <param name="algorithm">The JWS algorithm identifier (e.g. RS256, ES256) the signature must use.</param>
    /// <param name="data">The signing input bytes, BASE64URL(header) + '.' + BASE64URL(payload).</param>
    /// <param name="cancellationToken">Cancels the round-trip to the custodian.</param>
    /// <returns>The raw signature bytes in JWS wire format for the algorithm.</returns>
    Task<byte[]> SignAsync(
        string keyId,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken);

    /// <summary>
    /// Recovers a Content Encryption Key: an RSA decryption (RSA-OAEP / RSA-OAEP-256 / RSA1_5) or a symmetric
    /// unwrap (AES-KW / AES-GCM-KW), selected by <paramref name="algorithm"/>.
    /// </summary>
    /// <param name="keyId">The custodian's handle for the recipient key version.</param>
    /// <param name="algorithm">The JWE <c>alg</c> value identifying the key-management operation.</param>
    /// <param name="header">The JWE header; AES-GCM-KW reads its <c>iv</c> / <c>tag</c> parameters from it.</param>
    /// <param name="encryptedKey">The wrapped or RSA-encrypted CEK from the JWE Encrypted Key.</param>
    /// <param name="cancellationToken">Cancels the round-trip to the custodian.</param>
    /// <returns>The recovered CEK, or null on any failure. Returning null rather than throwing keeps a
    /// decryption failure indistinguishable from a wrong key, which the RFC 7516 §11.5 mitigation upstream
    /// relies on to close the Bleichenbacher / padding-oracle side channel.</returns>
    Task<byte[]?> UnwrapKeyAsync(
        string keyId,
        string algorithm,
        JsonWebTokenHeader header,
        byte[] encryptedKey,
        CancellationToken cancellationToken);

    /// <summary>
    /// Performs the ECDH-ES key agreement between the recipient's static private key (held by the custodian)
    /// and the originator's ephemeral public key, returning the raw shared secret Z. The library runs the
    /// Concat KDF over Z and any AES key unwrap, so those steps never leave it.
    /// </summary>
    /// <param name="keyId">The custodian's handle for the recipient key version.</param>
    /// <param name="algorithm">The JWE <c>alg</c> value (ECDH-ES or an ECDH-ES+A*KW variant).</param>
    /// <param name="ephemeralPublicKey">The originator's ephemeral public key from the <c>epk</c> header.</param>
    /// <param name="cancellationToken">Cancels the round-trip to the custodian.</param>
    /// <returns>The raw ECDH shared secret Z (the agreement's field-sized X-coordinate).</returns>
    Task<byte[]> AgreeKeyAsync(
        string keyId,
        string algorithm,
        JsonWebKey ephemeralPublicKey,
        CancellationToken cancellationToken);

    /// <summary>
    /// Enumerates every current version of the key named <paramref name="keyName"/> as its public half, each
    /// carrying the version-specific <c>kid</c> that routes a private operation back to that exact version, plus
    /// the custodian's creation time for that version. A custodian that does not version its keys yields a single
    /// element; a version-aware custodian (Vault Transit, Azure Key Vault) yields every version, which a rotation
    /// policy overlaps for zero-downtime key rollover. Called at publication time, so JWKS publishing and local
    /// signature verification run against the returned public halves and never touch the custodian on the hot path.
    /// </summary>
    /// <param name="keyName">The custodian's name for the logical key whose versions to enumerate.</param>
    /// <param name="cancellationToken">Cancels the round-trip to the custodian.</param>
    /// <returns>The key's versions, each a public-only <see cref="KeyVersion"/>.</returns>
    IAsyncEnumerable<KeyVersion> GetKeyVersionsAsync(
        string keyName,
        CancellationToken cancellationToken);
}
