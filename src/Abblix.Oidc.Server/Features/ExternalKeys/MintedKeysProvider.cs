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
using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Serves the keys the server minted for itself, opened from the ring and held in memory.
/// </summary>
/// <remarks>
/// The keys carry their private half, which is what makes the in-process signer own them: this tier routes
/// nothing to the custodian at issue time. Publication is where that matters most, so the private half is stripped
/// unless a caller explicitly asks for it, exactly as the static-configuration provider does.
/// </remarks>
internal sealed class MintedKeysProvider(KeyRing ring) : IAuthServiceKeysProvider
{
    /// <inheritdoc />
    public IAsyncEnumerable<JsonWebKey> GetSigningKeys(bool includePrivateKeys = false)
        => ring.Get(PublicKeyUsages.Signature, includePrivateKeys).ToAsyncEnumerable();

    /// <inheritdoc />
    public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(bool includePrivateKeys = false)
        => ring.Get(PublicKeyUsages.Encryption, includePrivateKeys).ToAsyncEnumerable();
}
