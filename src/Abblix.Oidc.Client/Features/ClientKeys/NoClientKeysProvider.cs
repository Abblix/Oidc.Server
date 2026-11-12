// Abblix OIDC Client Library
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

namespace Abblix.Oidc.Client.Features.ClientKeys;

/// <summary>
/// A client holding no keys of its own, which is what most clients are.
/// </summary>
/// <remarks>
/// Registered by default so that the verifier always has something to ask, and so that a client which
/// registered no encryption with its provider refuses an encrypted token rather than crashing on the way to
/// finding out it cannot read one. Refusing is the right answer there: a token encrypted for a client that
/// asked for no encryption is not a token this client can account for.
/// </remarks>
public sealed class NoClientKeysProvider : IClientKeysProvider
{
    /// <inheritdoc />
    public IAsyncEnumerable<JsonWebKey> GetDecryptionKeys(CancellationToken cancellationToken = default)
        => AsyncEnumerable.Empty<JsonWebKey>();
}
