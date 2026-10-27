// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Keeps the stream store and the outbox the host registered under keys of their own, as what every tenant shares,
/// so their unkeyed registrations can answer with the part of the tenant being served.
/// </summary>
internal static class SharedStores
{
    /// <summary>
    /// Registers the host's stream store and outbox once more under the keys every tenant's transmitter reads them by.
    /// </summary>
    public static void Keep(IServiceCollection services)
    {
        KeyedCopy<IStreamStore>(services, TenantTransmitters.SharedStoreKey);
        KeyedCopy<IEventOutbox>(services, TenantTransmitters.SharedOutboxKey);
    }

    /// <summary>
    /// Registers the last unkeyed registration of <typeparamref name="TService"/>, the one the container resolves,
    /// under <paramref name="key"/> with the same type, factory or instance and lifetime.
    /// </summary>
    /// <remarks>
    /// The container builds the keyed service as the host registered it, so it disposes what it built and leaves an
    /// instance the host handed it alone, as it would the unkeyed one.
    /// </remarks>
    private static void KeyedCopy<TService>(IServiceCollection services, string key)
    {
        var registered = services.Last(descriptor =>
            descriptor.ServiceType == typeof(TService) && !descriptor.IsKeyedService);

        services.Add(registered switch
        {
            { ImplementationType: { } type }
                => ServiceDescriptor.DescribeKeyed(typeof(TService), key, type, registered.Lifetime),

            { ImplementationFactory: { } factory }
                => ServiceDescriptor.DescribeKeyed(
                    typeof(TService),
                    key,
                    (provider, _) => factory(provider),
                    registered.Lifetime),

            { ImplementationInstance: { } instance }
                => ServiceDescriptor.KeyedSingleton(typeof(TService), key, instance),

            _ => throw new InvalidOperationException(
                $"The registration of {typeof(TService).Name} names no type, factory or instance."),
        });
    }
}
