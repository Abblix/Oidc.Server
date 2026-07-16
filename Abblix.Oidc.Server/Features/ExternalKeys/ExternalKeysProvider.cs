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
/// Publishes the public halves of an <see cref="IExternalKeyStore"/>'s signing and encryption keys to the OIDC
/// pipeline. It never returns private material: each key is public-only, which is precisely the signal the crypto
/// seam reads to route the private operation to the custodian by <c>kid</c>. The same public keys back the
/// <c>/jwks</c> endpoint and local signature verification. One provider serves any store, so the Vault and Azure
/// packages carry no key provider of their own.
/// </summary>
public sealed class ExternalKeysProvider : IAuthServiceKeysProvider
{
    private readonly Lazy<Task<JsonWebKey>> _signingKey;
    private readonly Lazy<Task<JsonWebKey>> _encryptionKey;

    /// <summary>
    /// Captures the key names to fetch; the public keys are pulled from the store lazily on first use.
    /// </summary>
    /// <param name="store">The external key store to fetch the public halves from.</param>
    /// <param name="signingKeyName">The store's name for the signing key, published as its <c>kid</c>.</param>
    /// <param name="encryptionKeyName">The store's name for the encryption key, published as its <c>kid</c>.</param>
    public ExternalKeysProvider(IExternalKeyStore store, string signingKeyName, string encryptionKeyName)
    {
        // Public keys are immutable for a given kid (rotation mints a new kid, never edits one), so each is fetched
        // from the store once at first use and cached for the life of the process.
        _signingKey = new(() => BuildPublicKeyAsync(
            store, signingKeyName, PublicKeyUsages.Signature, SigningAlgorithms.RS256));
        _encryptionKey = new(() => BuildPublicKeyAsync(
            store, encryptionKeyName, PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256));
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<JsonWebKey> GetSigningKeys(bool includePrivateKeys = false)
    {
        yield return await _signingKey.Value;
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(bool includePrivateKeys = false)
    {
        yield return await _encryptionKey.Value;
    }

    // An external key has no private half in this process, so includePrivateKeys is ignored: handing the pipeline
    // the public-only key both routes the private operation to the store (via the missing secret) and gives the
    // JWKS endpoint the exact key clients verify against.
    private static async Task<JsonWebKey> BuildPublicKeyAsync(
        IExternalKeyStore store, string keyName, string usage, string algorithm)
    {
        var parameters = await store.GetPublicKeyAsync(keyName, CancellationToken.None);

        // The parameters are public-only, so the JWK carries no private material: HasPrivateKey is false, and the
        // kid is the store's key name, which is also the custodian's handle.
        return new RsaJsonWebKey { KeyId = keyName, Usage = usage, Algorithm = algorithm }.Apply(parameters);
    }
}
