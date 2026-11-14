// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Encryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Jwt;

/// <summary>
/// Registers the token encryptor and the parts it is composed of.
/// </summary>
internal static class TokenEncryptionServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IJsonWebTokenEncryptor"/> with its encrypting and decrypting sides. A host's own
    /// encryptor wins, and then the parts are registered but never asked for.
    /// </summary>
    internal static IServiceCollection AddTokenEncryption(this IServiceCollection services)
    {
        services.TryAddSingleton<IJsonWebTokenEncryptor, JsonWebTokenEncryptor>();
        services.TryAddSingleton<JweEncryption>();
        services.TryAddSingleton<JweDecryption>();
        services.TryAddSingleton<JweDecryptionLog>();
        services.TryAddSingleton<JweKeyAttempt>();
        services.TryAddSingleton<LocalKeyEncryptor>();
        return services;
    }
}
