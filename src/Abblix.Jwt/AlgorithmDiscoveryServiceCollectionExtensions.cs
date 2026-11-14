// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Jwt;

/// <summary>
/// Registers what lists the algorithms the server supports.
/// </summary>
internal static class AlgorithmDiscoveryServiceCollectionExtensions
{
    /// <summary>
    /// Registers the providers of the signing and encryption algorithm sets.
    /// </summary>
    internal static IServiceCollection AddAlgorithmDiscovery(this IServiceCollection services)
    {
        // Discovery providers project the advertised algorithm sets from the live keyed
        // registrations, so an algorithm the host registers under its own 'alg'/'enc' key is
        // advertised automatically (signing_alg / encryption_alg / encryption_enc values).
        services.TryAddSingleton<SigningAlgorithmsProvider>();
        services.TryAddSingleton<EncryptionAlgorithmsProvider>();
        return services;
    }
}
