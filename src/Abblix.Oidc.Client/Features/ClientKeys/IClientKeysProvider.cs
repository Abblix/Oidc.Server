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
/// Supplies this client's own keys, as opposed to the provider's.
/// </summary>
/// <remarks>
/// The mirror of the signing keys provider, and the distinction is worth keeping straight: those are the
/// provider's public keys, held to check what it signed, and these are this client's own, held because
/// nobody else can hold them. A deployment that leaks the provider's keys has leaked nothing; one that
/// leaks these has leaked the ability to read everything encrypted for this client.
/// </remarks>
public interface IClientKeysProvider
{
    /// <summary>
    /// The keys that decrypt what the provider encrypted for this client.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>
    /// The private halves of the encryption keys this client published to the provider. Empty when the
    /// client registered no encryption, which is the ordinary case.
    /// </returns>
    /// <remarks>
    /// Every key is offered rather than the one the token names, for the same reason the signature check
    /// tries them all: the header is the sender's word about which key to use, and a recipient that
    /// searched by it would be taking direction from the message it has not yet opened.
    /// </remarks>
    IAsyncEnumerable<JsonWebKey> GetDecryptionKeys(CancellationToken cancellationToken = default);
}
