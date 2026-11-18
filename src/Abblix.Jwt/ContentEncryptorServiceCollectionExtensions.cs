// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Abblix.Jwt.Encryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Jwt;

/// <summary>
/// Registers the JWE content encryptors, keyed by 'enc'.
/// </summary>
internal static class ContentEncryptorServiceCollectionExtensions
{
    /// <summary>
    /// Registers the content encryptors <see cref="ServiceCollectionExtensions.AddJsonWebTokens"/> enables by default.
    /// </summary>
    internal static IServiceCollection AddDefaultContentEncryptors(this IServiceCollection services)
        => services
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384)
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes128Gcm)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes192Gcm)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

    /// <summary>
    /// Registers a content encryptor implementation for a specific JWE content encryption algorithm.
    /// Content encryptors handle the "enc" parameter in JWE headers (e.g., A256GCM, A128CBC-HS256).
    /// </summary>
    /// <typeparam name="TEncryptor">The IContentEncryptionAlgorithm implementation for encrypting/decrypting JWE
    /// content.</typeparam>
    /// <param name="services">The service collection to register the encryptor in.</param>
    /// <param name="algorithm">The JWE content encryption algorithm identifier (e.g., "A256GCM",
    /// "A128CBC-HS256").</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the encryptor as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the encryptor constructor via dependency injection override.
    /// Content encryption is performed after the Content Encryption Key (CEK) is encrypted/wrapped by the key
    /// encryptor.
    /// TryAdd dedups by (service, key) first-wins, so a host pre-registration for the algorithm wins
    /// over the built-in default.
    /// </remarks>
    private static IServiceCollection AddContentEncryptor<TEncryptor>(
        this IServiceCollection services,
        string algorithm)
        where TEncryptor : IContentEncryptionAlgorithm
    {
        services.TryAddKeyedSingleton<IContentEncryptionAlgorithm>(
            algorithm,
            (sp, _) => sp.CreateService<TEncryptor>(Dependency.Override(algorithm)));
        return services;
    }
}
