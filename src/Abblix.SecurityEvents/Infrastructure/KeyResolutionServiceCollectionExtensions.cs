// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// Wires how an issuer's signing keys are found.
/// </summary>
public static class KeyResolutionServiceCollectionExtensions
{
    /// <summary>
    /// Registers JWKS-based key resolution as the <see cref="IIssuerKeyResolver"/>: issuers'
    /// keys fetched from their published JWK Set documents and cached, with a forced refetch
    /// when a token names a key the cache has never seen.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">
    /// Where key sets live and how long they answer from cache; a Shared Signals receiver sets
    /// the URI selector from the transmitter's advertised "jwks_uri".</param>
    public static IServiceCollection AddJwksKeyResolution(
        this IServiceCollection services,
        Action<JwksKeyResolutionOptions>? configure = null)
    {
        services.AddHttpClient();

        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IIssuerKeyResolver, JwksIssuerKeyResolver>();

        return services;
    }

    /// <summary>
    /// Registers key resolution that asks each issuer where its keys are, reading "jwks_uri" from
    /// that issuer's discovery document instead of pinning an address at composition time.
    /// </summary>
    /// <remarks>
    /// Why an address pinned at composition time is worth removing:
    /// <see cref="JwksKeyResolutionOptions.UseDiscoveryDocument"/>.
    /// <para>
    /// A named entry and any selector answer first, so a host that knows better about one issuer
    /// keeps saying so; discovery stands where the well-known guess otherwise stands.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Cache lifetimes and any issuer-specific overrides, as usual.</param>
    public static IServiceCollection AddDiscoveryKeyResolution(
        this IServiceCollection services,
        Action<JwksKeyResolutionOptions>? configure = null)
        => services.AddJwksKeyResolution(options =>
        {
            options.UseDiscoveryDocument = true;
            configure?.Invoke(options);
        });
}
