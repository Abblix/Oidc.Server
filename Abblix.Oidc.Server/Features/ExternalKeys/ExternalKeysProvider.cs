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
/// Publishes the public halves of an <see cref="IKeyCustodian"/>'s signing and encryption keys to the OIDC
/// pipeline. It never returns private material: each key is public-only, which is precisely the signal the crypto
/// seam reads to route the private operation to the custodian by <c>kid</c>. The same public keys back the
/// <c>/jwks</c> endpoint and local signature verification. One provider serves any custodian, so the Vault and Azure
/// packages carry no key provider of their own.
/// </summary>
public sealed class ExternalKeysProvider(IKeyCustodian custodian, IExternalKeyConfiguration configuration)
    : IAuthServiceKeysProvider
{
    private JsonWebKey? _signingKey;

    /// <inheritdoc />
    public async IAsyncEnumerable<JsonWebKey> GetSigningKeys(bool includePrivateKeys = false)
    {
        var publicKey = await custodian.GetPublicKeyAsync(configuration.SigningKeyName, CancellationToken.None);

        // The custodian returns bare public-key material (RSA or EC); stamp the kid (= the store key name, the
        // custodian's handle), the use and the configured algorithm. record `with` keeps the runtime key type, so
        // this is correct for both RsaJsonWebKey and EllipticCurveJsonWebKey.
        _signingKey ??= publicKey with
        {
            Usage = PublicKeyUsages.Signature,
            KeyId = configuration.SigningKeyName,
            Algorithm = configuration.SigningAlgorithm,
        };

        yield return _signingKey;
    }

    private JsonWebKey? _encryptionKey;

    /// <inheritdoc />
    public async IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(bool includePrivateKeys = false)
    {
        var publicKey = await custodian.GetPublicKeyAsync(configuration.EncryptionKeyName, CancellationToken.None);

        // The custodian returns bare public-key material (RSA or EC); stamp the kid (= the store key name, the
        // custodian's handle), the use and the configured algorithm. record `with` keeps the runtime key type, so
        // this is correct for both RsaJsonWebKey and EllipticCurveJsonWebKey.
        _encryptionKey ??= publicKey with
        {
            Usage = PublicKeyUsages.Encryption,
            KeyId = configuration.EncryptionKeyName,
            Algorithm = configuration.EncryptionAlgorithm,
        };

        yield return _encryptionKey;
    }
}
