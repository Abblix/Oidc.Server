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

using System.Security.Cryptography;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Azure;

/// <summary>
/// Publishes the public halves of the Key Vault-held signing and encryption keys to the OIDC pipeline. It never
/// returns private material: each key is public-only, which is precisely the signal the crypto seam reads to
/// route the private operation to the Azure custodian by <c>kid</c>. The same public keys back the <c>/jwks</c>
/// endpoint and local signature verification.
/// </summary>
public sealed class AzureKeysProvider : IAuthServiceKeysProvider
{
    private readonly Lazy<Task<JsonWebKey>> _signingKey;
    private readonly Lazy<Task<JsonWebKey>> _encryptionKey;

    /// <summary>
    /// Captures the key names to fetch; the public keys are pulled from Key Vault lazily on first use.
    /// </summary>
    public AzureKeysProvider(AzureKeyVaultClient client, IOptions<AzureKeyVaultOptions> options)
    {
        var settings = options.Value;

        // Public keys are immutable for a given kid (rotation mints a new kid, never edits one), so each is
        // fetched from the vault once at first use and cached for the life of the process.
        _signingKey = new(() => BuildPublicKeyAsync(
            client, settings.SigningKeyName, PublicKeyUsages.Signature, SigningAlgorithms.RS256));
        _encryptionKey = new(() => BuildPublicKeyAsync(
            client, settings.EncryptionKeyName, PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256));
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
    // the public-only key both routes the private operation to Key Vault (via the missing secret) and gives the
    // JWKS endpoint the exact key clients verify against.
    private static async Task<JsonWebKey> BuildPublicKeyAsync(
        AzureKeyVaultClient client, string keyName, string usage, string algorithm)
    {
        var parameters = await client.GetPublicKeyAsync(keyName, CancellationToken.None);

        // The parameters are public-only, so the JWK carries no private material: HasPrivateKey is false, and the
        // kid is the Key Vault key name, which is also the custodian's handle.
        return new RsaJsonWebKey { KeyId = keyName, Usage = usage, Algorithm = algorithm }.Apply(parameters);
    }
}
