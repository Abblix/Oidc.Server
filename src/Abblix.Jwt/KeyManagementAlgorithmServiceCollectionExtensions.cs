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
/// Registers one JWE key-management algorithm, keyed by 'alg'.
/// </summary>
internal static class KeyManagementAlgorithmServiceCollectionExtensions
{
    /// <summary>
    /// Registers dir, which uses the shared symmetric key as the content encryption key itself.
    /// </summary>
    internal static IServiceCollection AddDirectEncryption(this IServiceCollection services)
        => services.AddKeyManagementAlgorithm<OctetJsonWebKey, DirectEncryption>(
            EncryptionAlgorithms.KeyManagement.Dir);

    /// <summary>
    /// Registers a key encryptor implementation for a specific JWE key management algorithm.
    /// Key encryptors handle the "alg" parameter in JWE headers (e.g., RSA-OAEP, A256GCMKW, dir).
    /// </summary>
    /// <typeparam name="TKey">The type of JSON Web Key this encryptor operates on (RsaJsonWebKey,
    /// OctetJsonWebKey, etc.).</typeparam>
    /// <typeparam name="TEncryptor">The IKeyManagementAlgorithm implementation for encrypting/decrypting Content
    /// Encryption Keys.</typeparam>
    /// <param name="services">The service collection to register the encryptor in.</param>
    /// <param name="algorithm">The JWE key management algorithm identifier (e.g., "RSA-OAEP-256", "A256GCMKW",
    /// "dir").</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the encryptor as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the encryptor constructor via dependency injection override.
    /// TryAdd dedups by (service, key) first-wins, so a host pre-registration for the algorithm wins
    /// over the built-in default.
    /// </remarks>
    internal static IServiceCollection AddKeyManagementAlgorithm<TKey, TEncryptor>(
        this IServiceCollection services,
        string algorithm)
        where TKey : JsonWebKey
        where TEncryptor : IKeyManagementAlgorithm<TKey>
    {
        services.TryAddKeyedSingleton<IKeyManagementAlgorithm<TKey>>(
            algorithm,
            (sp, _) => sp.CreateService<TEncryptor>(Dependency.Override(algorithm)));
        return services;
    }
}
