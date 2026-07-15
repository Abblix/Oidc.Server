// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Jwt;

/// <summary>
/// Host-implemented custodian for the external private keys the library never holds in process: they live in an
/// HSM, a cloud KMS, or a vault transit engine, and only the private operations cross the boundary. A key
/// published public-only routes its private operation here by <c>kid</c>: SIGNING for a signing key, and for a
/// decryption key an RSA/symmetric UNWRAP or an ECDH-ES AGREEMENT. The public operations - signature
/// verification, and wrapping a CEK with the recipient's public half - stay in process and never reach the
/// custodian. Wire it with <c>AddKeyCustodian</c>; a host with no external keys leaves it unregistered.
/// </summary>
/// <remarks>
/// Every operation is addressed by <c>kid</c>, the custodian's handle for the key, identical to the published
/// key's <c>kid</c> - there is no separate identifier and no mapping. The implementation never receives or
/// returns private key material, and only needs to implement the operations its own keys require: a signing-only
/// custodian leaves unwrap and agree unreachable, and a decryption-only custodian leaves sign unreachable.
/// Direct encryption (<c>dir</c>) and password-based key management (PBES2) have no external form - the CEK is
/// the secret itself, or is derived from it by a password KDF - so they are never routed here and fail closed.
/// </remarks>
public interface IKeyCustodian
{
    /// <summary>
    /// Signs <paramref name="data"/> with a signing key held by the custodian, returning the signature in the
    /// JWS wire format for <paramref name="algorithm"/>. Called for a signing key the library holds public-only.
    /// </summary>
    /// <param name="kid">The custodian's handle for the signing key.</param>
    /// <param name="algorithm">The JWS algorithm identifier (e.g. RS256, ES256) the signature must use.</param>
    /// <param name="data">The signing input bytes, BASE64URL(header) + '.' + BASE64URL(payload).</param>
    /// <param name="cancellationToken">Cancels the round-trip to the custodian.</param>
    /// <returns>The raw signature bytes in JWS wire format for the algorithm.</returns>
    ValueTask<byte[]> SignAsync(
        string kid,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken);

    /// <summary>
    /// Recovers a Content Encryption Key: an RSA decryption (RSA-OAEP / RSA-OAEP-256 / RSA1_5) or a symmetric
    /// unwrap (AES-KW / AES-GCM-KW), selected by <paramref name="algorithm"/>.
    /// </summary>
    /// <param name="kid">The custodian's handle for the recipient key.</param>
    /// <param name="algorithm">The JWE <c>alg</c> value identifying the key-management operation.</param>
    /// <param name="header">The JWE header; AES-GCM-KW reads its <c>iv</c> / <c>tag</c> parameters from it.</param>
    /// <param name="encryptedKey">The wrapped or RSA-encrypted CEK from the JWE Encrypted Key.</param>
    /// <param name="cancellationToken">Cancels the round-trip to the custodian.</param>
    /// <returns>The recovered CEK, or null on any failure. Returning null rather than throwing keeps a
    /// decryption failure indistinguishable from a wrong key, which the RFC 7516 §11.5 mitigation upstream
    /// relies on to close the Bleichenbacher / padding-oracle side channel.</returns>
    ValueTask<byte[]?> UnwrapKeyAsync(
        string kid,
        string algorithm,
        JsonWebTokenHeader header,
        byte[] encryptedKey,
        CancellationToken cancellationToken);

    /// <summary>
    /// Performs the ECDH-ES key agreement between the recipient's static private key (held by the custodian)
    /// and the originator's ephemeral public key, returning the raw shared secret Z. The library runs the
    /// Concat KDF over Z and any AES key unwrap, so those steps never leave it.
    /// </summary>
    /// <param name="kid">The custodian's handle for the recipient key.</param>
    /// <param name="algorithm">The JWE <c>alg</c> value (ECDH-ES or an ECDH-ES+A*KW variant).</param>
    /// <param name="ephemeralPublicKey">The originator's ephemeral public key from the <c>epk</c> header.</param>
    /// <param name="cancellationToken">Cancels the round-trip to the custodian.</param>
    /// <returns>The raw ECDH shared secret Z (the agreement's field-sized X-coordinate).</returns>
    ValueTask<byte[]> AgreeKeyAsync(
        string kid,
        string algorithm,
        JsonWebKey ephemeralPublicKey,
        CancellationToken cancellationToken);
}
