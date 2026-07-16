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

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// The transport to an external key store (an HSM, a cloud KMS, a vault) whose private half never enters this
/// process. It moves bytes across that boundary, addressed by key name and algorithm: the private operation is
/// performed inside the store, and the public half is fetched to publish and to verify locally. This is the only
/// surface a custodian package (Vault, Azure Key Vault, or a host's own store) has to implement; the generic
/// <see cref="ExternalKeyCustodian"/> and <see cref="ExternalKeysProvider"/> build the OIDC seams on top of it.
/// </summary>
/// <remarks>
/// Each implementation supports the algorithms its backend actually provisions and rejects the rest with a
/// <see cref="NotSupportedException"/>, so different stores expose different algorithm sets. The host selects the
/// signing and encryption algorithm per key through the store's options.
/// </remarks>
public interface IExternalKeyStore
{
    /// <summary>Signs the JWS signing input with the named key under the given JWS algorithm, returning the raw
    /// JWS signature bytes (R||S for EC, per RFC 7518 Section 3.4).</summary>
    /// <param name="keyName">The store's name for the key, which is also the published <c>kid</c>.</param>
    /// <param name="algorithm">The JWS signing algorithm (for example <c>RS256</c>, <c>PS384</c>, <c>ES256</c>).</param>
    /// <param name="data">The bytes to sign.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <exception cref="NotSupportedException">The store does not provision this algorithm.</exception>
    Task<byte[]> SignAsync(string keyName, string algorithm, byte[] data, CancellationToken cancellationToken);

    /// <summary>
    /// Unwraps (decrypts) a Content Encryption Key with the named key under the given JWE key-management
    /// algorithm. Returns null on a decryption failure so a wrong key or tampered ciphertext is indistinguishable,
    /// which the seam's padding-oracle mitigation depends on; an operational failure (bad auth, store unavailable)
    /// throws.
    /// </summary>
    /// <param name="keyName">The store's name for the key, which is also the published <c>kid</c>.</param>
    /// <param name="algorithm">The JWE key-management algorithm (for example <c>RSA-OAEP-256</c>).</param>
    /// <param name="ciphertext">The wrapped CEK.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <exception cref="NotSupportedException">The store does not provision this algorithm.</exception>
    Task<byte[]?> DecryptAsync(string keyName, string algorithm, byte[] ciphertext, CancellationToken cancellationToken);

    /// <summary>
    /// Derives the ECDH-ES shared secret from the named private EC key and the sender's ephemeral public key. Most
    /// managed stores do not expose a key-agreement primitive and throw; a store built on hardware that does can
    /// implement it.
    /// </summary>
    /// <param name="keyName">The store's name for the key, which is also the published <c>kid</c>.</param>
    /// <param name="algorithm">The JWE key-agreement algorithm (for example <c>ECDH-ES</c>).</param>
    /// <param name="ephemeralPublicKey">The sender's ephemeral public key from the JWE <c>epk</c> header.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <exception cref="NotSupportedException">The store does not expose key agreement.</exception>
    Task<byte[]> AgreeKeyAsync(
        string keyName, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken);

    /// <summary>
    /// Fetches the public half of the named key as a public-only <see cref="JsonWebKey"/> (RSA or EC, per the key
    /// the store holds), carrying only the key material. The caller stamps the <c>kid</c>, use and algorithm.
    /// Called once per key at startup, so JWKS publishing and signature verification run locally against it and
    /// never touch the store on the hot path.
    /// </summary>
    /// <param name="keyName">The store's name for the key.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    Task<JsonWebKey> GetPublicKeyAsync(string keyName, CancellationToken cancellationToken);
}
