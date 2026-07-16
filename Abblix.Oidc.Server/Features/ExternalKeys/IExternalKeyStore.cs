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

using System.Security.Cryptography;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// The transport to an external RSA key store (an HSM, a cloud KMS, a vault) whose private half never enters this
/// process. It moves bytes across that boundary, addressed by key name: signing and CEK unwrapping are performed
/// inside the store, and the public half is fetched to publish and to verify locally. This is the only surface a
/// custodian package (Vault, Azure Key Vault, or a host's own store) has to implement; the generic
/// <see cref="ExternalKeyCustodian"/> and <see cref="ExternalKeysProvider"/> build the OIDC seams on top of it.
/// </summary>
public interface IExternalKeyStore
{
    /// <summary>Signs the JWS signing input with the named RSA key, returning the raw JWS signature bytes.</summary>
    /// <param name="keyName">The store's name for the key, which is also the published <c>kid</c>.</param>
    /// <param name="data">The bytes to sign.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    Task<byte[]> SignAsync(string keyName, byte[] data, CancellationToken cancellationToken);

    /// <summary>
    /// Unwraps (decrypts) an RSA-OAEP-256 Content Encryption Key with the named RSA key. Returns null on a
    /// decryption failure so a wrong key or tampered ciphertext is indistinguishable, which the seam's
    /// padding-oracle mitigation depends on; an operational failure (bad auth, store unavailable) throws.
    /// </summary>
    /// <param name="keyName">The store's name for the key, which is also the published <c>kid</c>.</param>
    /// <param name="ciphertext">The wrapped CEK.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    Task<byte[]?> DecryptAsync(string keyName, byte[] ciphertext, CancellationToken cancellationToken);

    /// <summary>
    /// Fetches the public half of the named RSA key. Called once per key at startup, so JWKS publishing and
    /// signature verification run locally against it and never touch the store on the hot path.
    /// </summary>
    /// <param name="keyName">The store's name for the key, which is also the published <c>kid</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    Task<RSAParameters> GetPublicKeyAsync(string keyName, CancellationToken cancellationToken);
}
