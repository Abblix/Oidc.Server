// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Registers HTTP clients that initiate requests to client-supplied URLs (CIBA notification
/// endpoints, back-channel logout URIs, JWKS/issuer fetches). Every such client must route through
/// <see cref="SsrfValidatingHttpMessageHandler"/>; bundling the handler with the client registration
/// makes it impossible to add a new outbound client that silently skips SSRF protection.
/// </summary>
public static class SsrfHttpClientServiceCollectionExtensions
{
    /// <summary>
    /// Registers a typed HTTP client whose primary handler is the SSRF-validating handler.
    /// </summary>
    public static IHttpClientBuilder AddSsrfHttpClient<TClient, TImplementation>(
        this IServiceCollection services,
        Action<IServiceProvider, HttpClient> configureClient)
        where TClient : class
        where TImplementation : class, TClient
    {
        var builder = services
            .AddHttpClient<TClient, TImplementation>(configureClient)
            .ConfigurePrimaryHttpMessageHandler<SsrfValidatingHttpMessageHandler>();

        services.WatchTheGuardOn(builder.Name);
        return builder;
    }

    /// <summary>
    /// Registers a named HTTP client whose primary handler is the SSRF-validating handler.
    /// </summary>
    public static IHttpClientBuilder AddSsrfHttpClient(
        this IServiceCollection services,
        string name,
        Action<IServiceProvider, HttpClient> configureClient)
    {
        var builder = services
            .AddHttpClient(name, configureClient)
            .ConfigurePrimaryHttpMessageHandler<SsrfValidatingHttpMessageHandler>();

        services.WatchTheGuardOn(builder.Name);
        return builder;
    }

    /// <summary>
    /// Records the client as guarded and installs the watch that reports the guard's absence at handler-build time.
    /// </summary>
    /// <remarks>
    /// The registry is resolved out of the collection rather than through the provider, because the names have to
    /// accumulate across every registration call while the collection is still being built.
    /// </remarks>
    private static void WatchTheGuardOn(this IServiceCollection services, string name)
    {
        var guarded = services.FirstOrDefault(
            descriptor => descriptor.ServiceType == typeof(SsrfGuardedClients))?.ImplementationInstance
            as SsrfGuardedClients;

        if (guarded is null)
        {
            guarded = new SsrfGuardedClients();
            services.AddSingleton(guarded);
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IHttpMessageHandlerBuilderFilter, SsrfGuardWatch>());
        }

        guarded.Add(name);
    }
}
