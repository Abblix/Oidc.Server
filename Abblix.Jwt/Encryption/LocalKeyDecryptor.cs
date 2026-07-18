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

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The in-process decryption backend (<see cref="IContentKeyDecryptor"/>): owns keys that carry their private/secret
/// material and recovers the Content Encryption Key with them, dispatching to the keyed per-algorithm
/// <see cref="IKeyManagementAlgorithm{TJsonWebKey}"/>. It is one peer among the backends
/// <see cref="CompositeDecryptor"/> routes across; a public-only key is not its own (<see cref="CanDecrypt"/>
/// returns false), so such a key routes to an external backend, or - when this backend is resolved alone in the
/// uncomposed topology - fails loud, since a public-only key with no custodian is a misconfiguration.
/// </summary>
internal sealed class LocalKeyDecryptor(IServiceProvider serviceProvider) : IContentKeyDecryptor
{
    /// <summary>
    /// Owns any key that carries its private/secret material: in-process unwrap needs that half in memory.
    /// </summary>
    public bool CanDecrypt(JsonWebKey key) => key.HasPrivateKey;

    public Task<byte[]?> DecryptKeyAsync(
        JsonWebTokenHeader header,
        JsonWebKey key,
        string algorithm,
        byte[] encryptedKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // LocalKeyDecryptor owns only keys that carry their secret half (see CanDecrypt). When no custodian is
        // composed it is resolved as the sole decryptor, so it enforces its own ownership here too: a public-only
        // key with no custodian is a misconfiguration, not a decryption failure, so fail loud rather than silently
        // reject every inbound token for it. The RFC 7516 §11.5 uniform-null stays for real decryption failures,
        // which DecryptLocally returns.
        if (!key.HasPrivateKey)
            throw new InvalidOperationException(
                $"Decryption key (kid={key.KeyId}) has no secret material: it can only unwrap through an external " +
                "key custodian, but none is configured.");

        var contentEncryptionKey = DecryptLocally(key);
        return Task.FromResult(contentEncryptionKey);

        byte[]? DecryptLocally(JsonWebKey localKey) => localKey switch
        {
            RsaJsonWebKey rsaKey => TryDecryptBy(rsaKey),
            OctetJsonWebKey octetKey => TryDecryptBy(octetKey),
            EllipticCurveJsonWebKey ecKey => TryDecryptBy(ecKey),
            _ => null,
        };

        byte[]? TryDecryptBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var keyEncryptor = serviceProvider.GetKeyedService<IKeyManagementAlgorithm<TJsonWebKey>>(algorithm);
            return keyEncryptor != null && keyEncryptor.TryDecryptKey(header, jwk, encryptedKey, out var contentEncryptionKey)
                ? contentEncryptionKey
                : null;
        }
    }
}
