// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.RandomGenerators;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring
/// the generators of random identifiers and secrets.
/// </summary>
public static class RandomGeneratorsServiceCollectionExtensions
{
    /// <summary>
    /// Adds singleton services for generating random client IDs, client secrets, token IDs, and session IDs
    /// to the specified <see cref="IServiceCollection"/>.
    /// </summary>
    public static IServiceCollection AddRandomGenerators(this IServiceCollection services)
    {
        services.TryAddSingleton<IAuthorizationCodeGenerator, AuthorizationCodeGenerator>();
        services.TryAddSingleton<IAuthorizationRequestUriGenerator, AuthorizationRequestUriGenerator>();
        services.TryAddSingleton<IClientIdGenerator, ClientIdGenerator>();
        services.TryAddSingleton<IClientSecretGenerator, ClientSecretGenerator>();
        services.TryAddSingleton<ITokenIdGenerator, TokenIdGenerator>();
        services.TryAddSingleton<IGrantIdGenerator, GrantIdGenerator>();
        services.TryAddSingleton<ISessionIdGenerator, SessionIdGenerator>();
        return services;
    }
}
