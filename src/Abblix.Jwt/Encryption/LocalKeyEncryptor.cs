// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The in-process side of producing a JWE's key: picks the keyed <see cref="IKeyManagementAlgorithm{TJsonWebKey}"/>
/// for the key's type, as <see cref="LocalKeyDecryptor"/> does when the key is recovered.
/// </summary>
/// <param name="serviceProvider">Resolves the key management algorithms by their 'alg' name.</param>
internal sealed class LocalKeyEncryptor(IServiceProvider serviceProvider)
{
    /// <summary>
    /// Produces the Content Encryption Key and its wrapped form in process, dispatching to the keyed
    /// <see cref="IKeyManagementAlgorithm{TJsonWebKey}"/>. Asymmetric algorithms wrap with the recipient's
    /// public half; symmetric algorithms wrap with the locally held secret.
    /// </summary>
    public (byte[] ContentEncryptionKey, byte[] EncryptedKey) EncryptKey(
        JsonWebTokenHeader header,
        JsonWebKey key,
        string algorithm,
        int contentKeySizeInBytes)
    {
        // Encryption uses the recipient's public half (asymmetric) or a locally held shared secret (symmetric), so it
        // never needs a custodian - a symmetric key published without its secret cannot be wrapped and fails closed.
        if (key is OctetJsonWebKey { HasPrivateKey: false })
        {
            throw new InvalidOperationException(
                $"Encryption key (kid={key.KeyId}) has no secret material: a symmetric key wraps only " +
                "in process, and wrapping is never routed to an external custodian; failing closed.");
        }

        return key switch
        {
            RsaJsonWebKey rsaKey => EncryptBy(rsaKey),
            OctetJsonWebKey octetKey => EncryptBy(octetKey),
            EllipticCurveJsonWebKey ecKey => EncryptBy(ecKey),
            _ => throw new InvalidOperationException($"No key encryptor registered for key type: {key.GetType().Name}"),
        };

        (byte[], byte[]) EncryptBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var keyEncryptor = serviceProvider.GetRequiredKeyedService<IKeyManagementAlgorithm<TJsonWebKey>>(algorithm);
            var contentEncryptionKey = keyEncryptor.GenerateContentEncryptionKey(header, jwk, contentKeySizeInBytes);
            return (contentEncryptionKey, keyEncryptor.EncryptKey(header, jwk, contentEncryptionKey));
        }
    }
}
