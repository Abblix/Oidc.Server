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

namespace Abblix.Jwt.Signing;

/// <summary>
/// Host-implemented port that signs bytes with a private key held by an external custodian - an HSM, a
/// cloud KMS, or a vault transit engine - where the private key never enters application memory. The
/// library calls this when a configured signing key is published public-only (its private half is absent
/// from the key store). It is NOT registered by the library: a host with no external keys leaves it
/// unregistered, and the crypto router then serves signing entirely in process.
/// </summary>
/// <remarks>
/// The <c>kid</c> passed in is the custodian's handle for the key, identical to the key's published
/// <c>kid</c> - there is no separate identifier and no mapping. The implementation signs with its own key
/// material and returns the raw signature bytes in the JWS wire format for the algorithm; for ECDSA that
/// is the fixed-width R || S concatenation of RFC 7518 Section 3.4, not the ASN.1 DER encoding some SDKs
/// return. It never receives or returns private key material.
/// </remarks>
public interface IExternalSigner
{
    /// <summary>
    /// Signs <paramref name="data"/> with the external private key identified by <paramref name="kid"/>.
    /// </summary>
    /// <param name="kid">The key custodian's handle, identical to the published key's <c>kid</c>.</param>
    /// <param name="algorithm">The JWS algorithm identifier (e.g. RS256, ES256) the signature must use.</param>
    /// <param name="data">The signing input bytes, BASE64URL(header) + '.' + BASE64URL(payload).</param>
    /// <param name="cancellationToken">Cancels the signing round-trip to the custodian.</param>
    /// <returns>The raw signature bytes in JWS wire format for the algorithm.</returns>
    ValueTask<byte[]> SignAsync(
        string kid,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken);
}
