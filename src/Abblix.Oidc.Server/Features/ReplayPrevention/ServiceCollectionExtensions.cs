// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Jwt.ReplayPrevention;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

/// <summary>
/// Wires replay protection, which several unrelated features need and none of them owns:
/// JWT-bearer assertions (RFC 7523 Section 3), client assertions, and DPoP proofs
/// (RFC 9449 Section 11.1) all reserve identifiers in the same place.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// The prefix every entry this server writes carries. A stable literal on purpose: it was
    /// derived from a namespace that has since moved twice, and each move would have silently
    /// orphaned the entries of a running deployment, leaving a rolling upgrade with no replay
    /// protection for the length of its retention window. It is text now so that cannot happen
    /// again.
    /// </summary>
    private const string CacheKeyPrefix = "Abblix.Oidc.Server.Features.ReplayPrevention:";

    /// <summary>
    /// Registers the replay cache and the deprecated contract that still resolves to it.
    /// </summary>
    /// <remarks>
    /// Idempotent and TryAdd throughout, because three unrelated feature registrations call it
    /// and a host may have decided any part of it beforehand.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddReplayPrevention(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);

#pragma warning disable CS0618 // the deprecated contract is what this whole method is about
        var deprecated = services.FirstOrDefault(
            descriptor => descriptor.ServiceType == typeof(IJwtReplayCache));

        // Three feature registrations call this, and the decoration below is not idempotent by
        // itself - applying it twice would skew the window twice and log every reservation twice.
        // The shim registered at the end is the record that this already ran, and its
        // implementation type is what tells it apart from a host's own.
        if (deprecated is { ImplementationType: var implementation }
            && implementation == typeof(DistributedJwtReplayCache))
        {
            return services;
        }

        // A host that brought its own implementation of the deprecated contract keeps deciding
        // where replay state lives: bridging to it is what stops the move from quietly sidelining
        // an override that still looks registered.
        if (deprecated is not null)
        {
            services.TryAddSingleton<IReplayCache, LegacyReplayCacheBridge>();
        }
#pragma warning restore CS0618

        services.TryAddSingleton<IReplayCache>(provider =>
            provider.CreateService<DistributedReplayCache>(Dependency.Override(CacheKeyPrefix)));

        // Decorated rather than composed in one factory, so this server's policy also reaches a
        // store some other package registered first - a host running both this server and a
        // Security Event Token receiver shares one replay store, and which of them registered it
        // must not decide whether the server's clock skew and log events apply.
        services.Decorate<IReplayCache, ConfiguredReplayCache>();

#pragma warning disable CS0618 // deliberate registration of the deprecated shim
        services.TryAddSingleton<IJwtReplayCache, DistributedJwtReplayCache>();
#pragma warning restore CS0618

        return services;
    }
}
