// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Encryption;
using Microsoft.Extensions.DependencyInjection;
using KeyManagement = Abblix.Jwt.EncryptionAlgorithms.KeyManagement;

namespace Abblix.Jwt;

/// <summary>
/// Registers the JWE key-management algorithms enabled by default.
/// </summary>
internal static class KeyManagementServiceCollectionExtensions
{
    /// <summary>
    /// Registers the key-management algorithms <see cref="ServiceCollectionExtensions.AddJsonWebTokens"/> enables by
    /// default. RSA-OAEP and RSA-OAEP-256 are the recommended RSA algorithms; RSA1_5 and PBES2 are opt-in.
    /// </summary>
    internal static IServiceCollection AddDefaultKeyManagementAlgorithms(this IServiceCollection services)
        => services
            .AddKeyManagementAlgorithm<RsaJsonWebKey, RsaKeyEncryptor>(KeyManagement.RsaOaep)
            .AddKeyManagementAlgorithm<RsaJsonWebKey, RsaKeyEncryptor>(KeyManagement.RsaOaep256)

            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(KeyManagement.Aes128Gcmkw)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(KeyManagement.Aes192Gcmkw)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(KeyManagement.Aes256Gcmkw)

            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesKeyWrapEncryptor>(KeyManagement.Aes128KW)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesKeyWrapEncryptor>(KeyManagement.Aes192KW)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesKeyWrapEncryptor>(KeyManagement.Aes256KW)

            .AddDirectKeyAgreement()

            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(KeyManagement.EcdhEs)
            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(KeyManagement.EcdhEsAes128KW)
            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(KeyManagement.EcdhEsAes192KW)
            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(KeyManagement.EcdhEsAes256KW);
}
