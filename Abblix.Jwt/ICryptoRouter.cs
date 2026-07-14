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
/// Routes a private-key cryptographic byte operation to the in-process keyed primitive when the key
/// carries its secret material, and (in later work) to an external key custodian when it does not,
/// failing closed when neither can serve it. This keeps the "is the secret present locally?" decision
/// in a single place, so the JWT orchestrators - and the non-JOSE protected-data seal that will share
/// it - never re-implement the fail-closed rule.
/// </summary>
/// <remarks>
/// An external key is an ordinary published JWK whose secret half is simply absent from the key store:
/// for an asymmetric key the private parameters are missing, for a symmetric key the key bytes are
/// missing. Its <c>kid</c> is the custodian's handle for the private material - there is no marker on
/// the key, no reference type, and no registry. The router operates on bytes plus a public-key identity
/// and never materialises private key material of its own.
/// </remarks>
internal interface ICryptoRouter
{
    /// <summary>
    /// Produces the signature over <paramref name="data"/> for the given signing key and algorithm.
    /// When the key carries private material the signature is computed in process by the keyed
    /// <see cref="Signing.IDataSigner{TJsonWebKey}"/>; a public-only key fails closed here until an
    /// external signer is wired (in the remote-signing work).
    /// </summary>
    /// <param name="signingKey">The signing key; the presence of private material selects the local path.</param>
    /// <param name="algorithm">The JWS algorithm identifier, which is the keyed-primitive DI key.</param>
    /// <param name="data">The signing input bytes, BASE64URL(header) + '.' + BASE64URL(payload).</param>
    /// <param name="cancellationToken">Cancels a network-backed external signing round-trip.</param>
    /// <returns>The signature bytes.</returns>
    ValueTask<byte[]> SignAsync(
        JsonWebKey signingKey,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken);

    /// <summary>
    /// Produces the Content Encryption Key and its wrapped form for creating a JWE. Asymmetric key
    /// management (RSA, ECDH-ES) runs in process against the recipient's public half, so it is local even
    /// for an external key; a symmetric key whose secret bytes are absent is wrapped by an external
    /// custodian; direct and password-based key management have no external form and fail closed.
    /// </summary>
    /// <param name="header">The JWE header; key management may add parameters (epk, iv, tag) to it.</param>
    /// <param name="encryptionKey">The recipient key the JWE is encrypted with.</param>
    /// <param name="algorithm">The JWE <c>alg</c> (key-management) identifier.</param>
    /// <param name="contentKeySizeInBytes">The CEK size the content encryption algorithm requires.</param>
    /// <param name="cancellationToken">Cancels a network-backed external wrap.</param>
    /// <returns>The Content Encryption Key and the JWE Encrypted Key bytes.</returns>
    ValueTask<(byte[] contentEncryptionKey, byte[] encryptedKey)> EncryptKeyAsync(
        JsonWebTokenHeader header,
        JsonWebKey encryptionKey,
        string algorithm,
        int contentKeySizeInBytes,
        CancellationToken cancellationToken);

    /// <summary>
    /// Recovers the Content Encryption Key from a JWE Encrypted Key. A key with secret material unwraps in
    /// process; a public-only key routes the private operation - RSA decrypt, ECDH agreement, or symmetric
    /// unwrap - to an external custodian. Returns null on any decryption failure so a wrong key is
    /// indistinguishable from a bad ciphertext (the RFC 7516 §11.5 mitigation upstream relies on this);
    /// fails closed by throwing only on misconfiguration (an external key with no port or no external form).
    /// </summary>
    /// <param name="header">The JWE header carrying algorithm parameters (epk, iv, tag, apu, apv).</param>
    /// <param name="decryptionKey">The candidate recipient key.</param>
    /// <param name="algorithm">The JWE <c>alg</c> (key-management) identifier.</param>
    /// <param name="encryptedKey">The JWE Encrypted Key bytes.</param>
    /// <param name="cancellationToken">Cancels a network-backed external unwrap or agreement.</param>
    /// <returns>The recovered CEK, or null on a decryption failure.</returns>
    ValueTask<byte[]?> DecryptKeyAsync(
        JsonWebTokenHeader header,
        JsonWebKey decryptionKey,
        string algorithm,
        byte[] encryptedKey,
        CancellationToken cancellationToken);
}
