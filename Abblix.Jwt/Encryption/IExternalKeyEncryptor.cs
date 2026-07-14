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

namespace Abblix.Jwt.Encryption;

/// <summary>
/// Host-implemented port for JWE key-management operations whose private/secret key is held by an
/// external custodian - an HSM, a cloud KMS, or a vault transit engine - where the key never enters
/// application memory. The library calls it only for the operations that genuinely need the secret half:
/// asymmetric encryption stays in process because it uses the recipient's public half, so only unwrap and
/// ECDH agreement are remote; symmetric wrap and unwrap are remote in both directions. It is NOT
/// registered by the library: a host with no external keys leaves it unregistered.
/// </summary>
/// <remarks>
/// Every operation is addressed by <c>kid</c>, which is the custodian's handle for the key, identical to
/// the published key's <c>kid</c> - there is no separate identifier and no mapping. The implementation
/// never receives or returns private key material. Direct encryption (<c>dir</c>) and password-based
/// key management (PBES2) have no external form - the CEK is the secret itself, or is derived from it by
/// a password KDF - so they are never routed here and fail closed instead.
/// </remarks>
public interface IExternalKeyEncryptor
{
    /// <summary>
    /// Recovers a Content Encryption Key: an RSA decryption (RSA-OAEP / RSA-OAEP-256 / RSA1_5) or a
    /// symmetric unwrap (AES-KW / AES-GCM-KW), selected by <paramref name="algorithm"/>.
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
    /// Wraps a Content Encryption Key with a symmetric key management algorithm (AES-KW / AES-GCM-KW).
    /// </summary>
    /// <param name="kid">The custodian's handle for the recipient key.</param>
    /// <param name="algorithm">The JWE <c>alg</c> value identifying the wrap operation.</param>
    /// <param name="header">The JWE header; AES-GCM-KW writes its <c>iv</c> / <c>tag</c> parameters into it.</param>
    /// <param name="contentEncryptionKey">The CEK to wrap.</param>
    /// <param name="cancellationToken">Cancels the round-trip to the custodian.</param>
    /// <returns>The wrapped CEK for the JWE Encrypted Key.</returns>
    ValueTask<byte[]> WrapKeyAsync(
        string kid,
        string algorithm,
        JsonWebTokenHeader header,
        byte[] contentEncryptionKey,
        CancellationToken cancellationToken);

    /// <summary>
    /// Performs the ECDH-ES key agreement between the recipient's static private key (held by the
    /// custodian) and the originator's ephemeral public key, returning the raw shared secret Z. The
    /// library runs the Concat KDF over Z and any AES key unwrap, so those steps never leave it.
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

    /// <summary>
    /// Seals arbitrary bytes under an external symmetric key using authenticated encryption, binding the
    /// given associated data. This is the generic counterpart to <see cref="WrapKeyAsync"/> for the
    /// non-JOSE reversible-subject protection; it is defined now so the port never has to grow later.
    /// </summary>
    /// <param name="kid">The custodian's handle for the symmetric key.</param>
    /// <param name="plaintext">The bytes to seal.</param>
    /// <param name="associatedData">The associated data bound by the AEAD (not encrypted, authenticated).</param>
    /// <param name="cancellationToken">Cancels the round-trip to the custodian.</param>
    /// <returns>The sealed blob (nonce, ciphertext and tag as the implementation lays them out).</returns>
    ValueTask<byte[]> SealAsync(
        string kid,
        byte[] plaintext,
        byte[] associatedData,
        CancellationToken cancellationToken);

    /// <summary>
    /// Opens a blob produced by <see cref="SealAsync"/> under the same key and associated data.
    /// </summary>
    /// <param name="kid">The custodian's handle for the symmetric key.</param>
    /// <param name="sealedData">The blob previously produced by <see cref="SealAsync"/>.</param>
    /// <param name="associatedData">The associated data that must match what was sealed.</param>
    /// <param name="cancellationToken">Cancels the round-trip to the custodian.</param>
    /// <returns>The recovered plaintext, or null when authentication fails (tamper or wrong key).</returns>
    ValueTask<byte[]?> OpenAsync(
        string kid,
        byte[] sealedData,
        byte[] associatedData,
        CancellationToken cancellationToken);
}
