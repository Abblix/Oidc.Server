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
/// A host callback that signs bytes with a signing key held by an external custodian (HSM, cloud KMS, or a
/// vault transit engine), addressed by its <c>kid</c> and never seeing private material. Pass it to
/// <c>AddExternalSigner</c> to route a public-only signing key to the custodian without writing a full
/// <see cref="IDataSigner"/> decorator; a host that wants more control (multiple custodians, custom routing)
/// writes its own decorator over <see cref="IDataSigner"/> instead.
/// </summary>
/// <param name="kid">The custodian's handle, identical to the published key's <c>kid</c>.</param>
/// <param name="algorithm">The JWS algorithm identifier (e.g. RS256, ES256) the signature must use.</param>
/// <param name="data">The signing input bytes, BASE64URL(header) + '.' + BASE64URL(payload).</param>
/// <param name="cancellationToken">Cancels the round-trip to the custodian.</param>
/// <returns>The raw signature bytes in JWS wire format for the algorithm.</returns>
public delegate ValueTask<byte[]> ExternalSignHandler(
    string kid,
    string algorithm,
    byte[] data,
    CancellationToken cancellationToken);
