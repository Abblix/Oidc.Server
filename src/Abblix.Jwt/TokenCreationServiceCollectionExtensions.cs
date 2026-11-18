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
/// Registers the token creator and the issuer of a Nested JWT it hands the work to.
/// </summary>
internal static class TokenCreationServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IJsonWebTokenCreator"/> and the issuer behind it. A host's own creator wins, and then
    /// the issuer is registered but never asked for.
    /// </summary>
    internal static IServiceCollection AddTokenCreation(this IServiceCollection services)
    {
        services.TryAddSingleton<IJsonWebTokenCreator, JsonWebTokenCreator>();
        services.TryAddSingleton<NestedJwtIssuer>();
        return services;
    }
}
