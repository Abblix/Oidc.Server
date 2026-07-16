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
/// Adapts an <see cref="IExternalKeyStore"/> to the <see cref="IKeyCustodian"/> seam: it performs the private
/// operations for keys the provider publishes public-only, addressed by the <c>kid</c> (which is the store's key
/// name). It is a thin passthrough - the store owns which algorithms it supports and rejects the rest, so this
/// custodian carries no algorithm policy of its own and serves any store. The JWE header is not forwarded: the
/// key-management <c>algorithm</c> is all the store needs to unwrap.
/// </summary>
public sealed class ExternalKeyCustodian(IExternalKeyStore store) : IKeyCustodian
{
    /// <inheritdoc />
    public ValueTask<byte[]> SignAsync(
        string kid, string algorithm, byte[] data, CancellationToken cancellationToken)
        => new(store.SignAsync(kid, algorithm, data, cancellationToken));

    /// <inheritdoc />
    public ValueTask<byte[]?> UnwrapKeyAsync(
        string kid, string algorithm, JsonWebTokenHeader header, byte[] encryptedKey, CancellationToken cancellationToken)
        => new(store.DecryptAsync(kid, algorithm, encryptedKey, cancellationToken));

    /// <inheritdoc />
    public ValueTask<byte[]> AgreeKeyAsync(
        string kid, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken)
        => new(store.AgreeKeyAsync(kid, algorithm, ephemeralPublicKey, cancellationToken));
}
