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
/// The JWE key-recovery seam: recovers the Content Encryption Key for a recipient key, routed per key to the
/// backend that owns it. This is the encryption counterpart of <see cref="Signing.IDataSigner"/> and, like it,
/// carries ONLY the private operation: recovering the CEK needs the recipient's private/secret half, so a
/// public-only key routes to an external custodian. Producing a JWE (wrapping the CEK) uses the recipient's
/// PUBLIC half for asymmetric algorithms, or a locally held shared secret for symmetric ones, so it never needs
/// a custodian and never passes through this seam - it stays in <see cref="IJsonWebTokenEncryptor"/>, exactly as
/// signature verification stays out of <see cref="Signing.IDataSigner"/>. Backends compose as peers behind
/// <see cref="CompositeDataDecryptor"/>: <see cref="LocalKeyDecryptor"/> unwraps in process, an external
/// custodian backend (<see cref="ExternalKeyDecryptor"/>) unwraps against an HSM/KMS/vault.
/// </summary>
public interface IDataDecryptor
{
    /// <summary>
    /// Reports whether this backend owns recovering the CEK for <paramref name="key"/>. The in-process backend
    /// owns any key that carries its private/secret material; an external custodian backend owns any key
    /// published public-only, whose private half lives with the custodian.
    /// </summary>
    /// <param name="key">The recipient decryption key the seam is about to route.</param>
    /// <returns><c>true</c> if this backend can recover the CEK for <paramref name="key"/>.</returns>
    bool CanDecrypt(JsonWebKey key);

    /// <summary>
    /// Recovers the Content Encryption Key from <paramref name="encryptedKey"/>: an RSA decryption, a symmetric
    /// unwrap, or an ECDH-ES agreement, selected by <paramref name="algorithm"/>. Returns null on any failure so
    /// a wrong key is indistinguishable from a bad ciphertext (the RFC 7516 §11.5 mitigation upstream relies on
    /// this) and never throws on the attacker-supplied header.
    /// </summary>
    /// <param name="header">The JWE header; ECDH-ES and AES-GCM key wrap read parameters from it.</param>
    /// <param name="key">The recipient decryption key. Its <c>kid</c> is the custodian's handle when external.</param>
    /// <param name="algorithm">The JWE <c>alg</c> value identifying the key-management operation.</param>
    /// <param name="encryptedKey">The wrapped or RSA-encrypted CEK from the JWE Encrypted Key.</param>
    /// <param name="cancellationToken">Cancels the operation, including a custodian round-trip.</param>
    /// <returns>The recovered CEK, or null on any failure.</returns>
    ValueTask<byte[]?> DecryptKeyAsync(
        JsonWebTokenHeader header,
        JsonWebKey key,
        string algorithm,
        byte[] encryptedKey,
        CancellationToken cancellationToken);
}
