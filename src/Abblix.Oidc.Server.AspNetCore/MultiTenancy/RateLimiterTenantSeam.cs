// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Threading.RateLimiting;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// A budget spent per caller, of which each tenant gets a limiter of its own, built the way the budget was
/// registered.
/// </summary>
/// <remarks>
/// Built rather than wrapped, because a limiter partitions by the resource it is handed: a host's own limiter was
/// written for a client id or an address, and a key carrying the tenant would reach it as neither.
/// </remarks>
/// <inheritdoc cref="TenantSeam{TService, TWrapper}"/>
/// <typeparam name="TResource">What the budget is partitioned by.</typeparam>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal sealed class RateLimiterTenantSeam<TResource>(object key, bool required = true)
    : TenantSeam<PartitionedRateLimiter<TResource>, TenantPartitionedRateLimiter<TResource>>(key, required)
{
    /// <inheritdoc />
    protected override void WrapRegistration(IServiceCollection services, int index)
    {
        var registered = services[index];
        if (registered.KeyedImplementationInstance is not null)
        {
            throw new InvalidOperationException(
                $"{Name} is registered as a ready instance, which every tenant would share, so one tenant's " +
                "callers would spend another's budget. Register it with a factory or a type, so that " +
                $"{nameof(MultiTenancyExtensions.AddMultiTenancy)}() can build one for each tenant.");
        }

        services[index] = ServiceDescriptor.DescribeKeyed(
            registered.ServiceType,
            registered.ServiceKey,
            (serviceProvider, _) => new TenantPartitionedRateLimiter<TResource>(
                () => Build(serviceProvider, registered),
                serviceProvider.GetRequiredService<ITenantAccessor>()),
            registered.Lifetime);
    }

    private static PartitionedRateLimiter<TResource> Build(IServiceProvider serviceProvider, ServiceDescriptor registered)
        => registered switch
        {
            { KeyedImplementationFactory: { } factory }
                => (PartitionedRateLimiter<TResource>)factory(serviceProvider, registered.ServiceKey),

            { KeyedImplementationType: { } type }
                => (PartitionedRateLimiter<TResource>)ActivatorUtilities.CreateInstance(serviceProvider, type),

            _ => throw new InvalidOperationException(
                $"The registration of {registered.ServiceType.Name} '{registered.ServiceKey}' names neither a " +
                "factory nor a type, and a ready instance was refused when it was wrapped."),
        };
}
