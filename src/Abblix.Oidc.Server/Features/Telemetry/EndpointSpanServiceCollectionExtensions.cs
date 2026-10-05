// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Wraps an endpoint's handler in the span of its endpoint.
/// </summary>
internal static class EndpointSpanServiceCollectionExtensions
{
    /// <summary>
    /// Wraps the registered <typeparamref name="THandler"/> in <typeparamref name="TDecorator"/>, once however often the
    /// endpoint's registration method runs.
    /// </summary>
    public static IServiceCollection AddEndpointSpan<THandler, TDecorator>(this IServiceCollection services)
        where THandler : class
        where TDecorator : class, THandler
    {
        var registered = services
            .Select(descriptor => descriptor.ImplementationInstance)
            .OfType<EndpointSpansRegistered>()
            .SingleOrDefault();

        if (registered is null)
        {
            registered = new EndpointSpansRegistered();
            services.AddSingleton(registered);
        }

        return registered.Decorators.Add(typeof(TDecorator))
            ? services.Decorate<THandler, TDecorator>()
            : services;
    }
}
