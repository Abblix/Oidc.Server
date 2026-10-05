// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Wraps a service in the decorator that measures its calls.
/// </summary>
internal static class TelemetryServiceCollectionExtensions
{
    /// <summary>
    /// Wraps the registered <typeparamref name="THandler"/> in <typeparamref name="TDecorator"/>, once however often the
    /// registration method of the service runs.
    /// </summary>
    public static IServiceCollection AddTelemetryDecorator<THandler, TDecorator>(this IServiceCollection services)
        where THandler : class
        where TDecorator : class, THandler
    {
        var registered = services
            .Select(descriptor => descriptor.ImplementationInstance)
            .OfType<TelemetryDecoratorsRegistered>()
            .SingleOrDefault();

        if (registered is null)
        {
            registered = new TelemetryDecoratorsRegistered();
            services.AddSingleton(registered);

            // The meter comes from the host's factory, which an ASP.NET Core host registers already; the call adds
            // one only where none is.
            services.AddMetrics();
            services.TryAddSingleton<OidcInstruments>();
        }

        return registered.Decorators.Add(typeof(TDecorator))
            ? services.Decorate<THandler, TDecorator>()
            : services;
    }
}
