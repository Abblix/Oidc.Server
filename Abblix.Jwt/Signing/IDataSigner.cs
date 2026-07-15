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
/// Signs abstract byte data with a server signing key: it resolves the algorithm implementation from the
/// key and performs the private operation in process (when the key carries private material) or against an
/// external key custodian (when it is published public-only). This is the routed, byte-level counterpart of
/// the token-level <see cref="IJsonWebTokenSigner"/>: because it works with bytes rather than a whole token,
/// an HSM/KMS/vault integration decorates or composes over it (see <see cref="ExternalKeySigner"/>) without
/// touching JWS framing.
/// </summary>
public interface IDataSigner
{
    /// <summary>
    /// Produces the signature bytes for <paramref name="data"/> under <paramref name="algorithm"/> using
    /// <paramref name="key"/>, in the JWS wire format for the algorithm.
    /// </summary>
    /// <param name="key">The signing key. Its <c>kid</c> is the custodian's handle when it is external.</param>
    /// <param name="algorithm">The JWS algorithm identifier (e.g. RS256, ES256) the signature must use.</param>
    /// <param name="data">The signing input bytes, BASE64URL(header) + '.' + BASE64URL(payload).</param>
    /// <param name="cancellationToken">Cancels the signing operation, including a custodian round-trip.</param>
    /// <returns>The raw signature bytes in JWS wire format for the algorithm.</returns>
    ValueTask<byte[]> SignAsync(
        JsonWebKey key,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken);
}
