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
/// Registers the token validator and the parts it is composed of.
/// </summary>
internal static class ValidationServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IJsonWebTokenValidator"/> with its JWS and JWE sides and the two chains of the JWS side.
    /// A host's own validator wins, and then the parts are registered but never asked for.
    /// </summary>
    internal static IServiceCollection AddTokenValidation(this IServiceCollection services)
    {
        services.TryAddSingleton<IJsonWebTokenValidator, JsonWebTokenValidator>();
        services.TryAddSingleton<JwsValidation>();
        services.TryAddSingleton<JwsHeaderChain>();
        services.TryAddSingleton<JwtClaimsChain>();
        services.TryAddSingleton<JweValidation>();
        return services;
    }
}
