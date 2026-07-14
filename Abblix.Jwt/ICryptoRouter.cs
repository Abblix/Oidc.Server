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
}
