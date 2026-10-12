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
/// This client's keys, held by the host and handed over as they are.
/// </summary>
/// <param name="decryptionKeys">
/// The private halves of the encryption keys this client published to its provider.
/// </param>
/// <remarks>
/// The keys are in memory for the life of the application, which is what a key used on every request has to
/// be. Where they came from is the host's business and deliberately not this library's: a file, a secret
/// store, a hardware module behind a custom implementation of the contract.
/// </remarks>
public sealed class ConfiguredClientKeysProvider(IReadOnlyCollection<JsonWebKey> decryptionKeys)
    : IClientKeysProvider
{
    /// <inheritdoc />
    public async IAsyncEnumerable<JsonWebKey> GetDecryptionKeys(
        [System.Runtime.CompilerServices.EnumeratorCancellation]
        CancellationToken cancellationToken = default)
    {
        foreach (var key in decryptionKeys)
            yield return key;

        await Task.CompletedTask;
    }
}
