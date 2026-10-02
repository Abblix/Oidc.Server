// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring
/// outbound HTTP fetching guarded against SSRF.
/// </summary>
public static class SecureHttpFetchServiceCollectionExtensions
{
    /// <summary>
    /// Registers secure HTTP fetching services with SSRF (Server-Side Request Forgery) protection.
    /// This method configures the HTTP client for fetching external content (such as sector identifier URIs
    /// and request URIs) and decorates it with validation to prevent SSRF attacks.
    /// </summary>
    /// <remarks>
    /// The registered services include:
    /// - A typed HTTP client (<see cref="SecureHttpFetcher"/>) for making secure HTTP requests
    /// - A custom message handler (<see cref="SsrfValidatingHttpMessageHandler"/>) that provides comprehensive SSRF protection
    ///
    /// The SSRF protection includes:
    /// - Blocking requests to internal hostnames (localhost, internal, etc.)
    /// - Blocking requests to internal TLDs (.local, .internal, etc.)
    /// - DNS resolution and blocking of private/reserved IP address ranges
    /// - Re-validation of DNS before HTTP request to prevent DNS rebinding attacks (TOCTOU)
    /// - HTTP redirect disabling to prevent redirect-based SSRF bypass
    /// - Response size and timeout limits (configurable via <see cref="SecureHttpFetchOptions"/>)
    ///
    /// The multi-layered protection strategy follows OWASP SSRF Prevention guidelines and provides
    /// defense-in-depth against various SSRF attack vectors including DNS rebinding and redirect-based bypasses.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <param name="configure">Optional configuration action to customize <see cref="SecureHttpFetchOptions"/>.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddSecureHttpFetch(
        this IServiceCollection services,
        Action<SecureHttpFetchOptions>? configure = null)
    {
        // Register and configure options
        var optionsBuilder = services.AddOptions<SecureHttpFetchOptions>();

        if (configure != null)
        {
            optionsBuilder.Configure(configure);
        }

        // The framework resolves every registered validator, so this joins the set rather than replacing
        // whatever a host registered for the same options.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<SecureHttpFetchOptions>, SecureHttpFetchOptionsValidator>());

        services.TryAddSingleton<ISecureUriValidator, SecureUriValidator>();
        // Built here rather than by the container's own constructor selection, which would fill the handler's
        // optional resolution parameter from any registration of that delegate - a registration a host may well
        // have made for something else entirely, silently deciding what every outbound address of this server
        // resolves to. A host that means to replace the resolution registers this handler itself.
        services.TryAddTransient(serviceProvider => new SsrfValidatingHttpMessageHandler(
            serviceProvider.GetRequiredService<IOptions<SecureHttpFetchOptions>>(),
            serviceProvider.GetRequiredService<ISecureUriValidator>()));

        services.AddSsrfHttpClient<ISecureHttpFetcher, SecureHttpFetcher>((serviceProvider, client) =>
        {
            var options = serviceProvider.GetRequiredService<IOptions<SecureHttpFetchOptions>>().Value;
            client.Timeout = options.RequestTimeout;
        });

        // One cached fetcher per consumer, each keyed by who asks and carrying its own lifetime. Caching used
        // to hang off a single service key that only the JWT bearer grant read, so client, software-statement
        // and resource key sets were fetched over the network on every use. Giving each consumer its own
        // instance keeps the lifetime a property of the caller without putting it into the transport contract:
        // how stale a document may be depends on what it is used for, and a resource key set backing every
        // token issued is not the same case as a client key set read on the occasional request object.
        services.AddCachedSecureHttpFetcher(
            KeySetOwners.Client,
            fetch => fetch.ClientKeysCacheDuration);

        services.AddCachedSecureHttpFetcher(
            KeySetOwners.Resource,
            fetch => fetch.ResourceKeysCacheDuration);

        services.AddCachedSecureHttpFetcher(
            KeySetOwners.SoftwareStatementIssuer,
            fetch => fetch.SoftwareStatementKeysCacheDuration);

        // The JWT bearer grant keeps its own long-standing setting, which lives with the rest of that
        // feature's options rather than here.
        services.DecorateKeyed<ISecureHttpFetcher, CachingSecureHttpFetcherDecorator>(
            KeySetOwners.Issuer,
            Dependency.Override(serviceProvider => serviceProvider
                .GetRequiredService<IOptionsMonitor<OidcOptions>>()
                .CurrentValue.JwtBearer.JwksCacheDuration));

        return services;
    }

    /// <summary>
    /// Registers a caching <see cref="ISecureHttpFetcher"/> for one consumer, under its own service key and
    /// with its own cache lifetime.
    /// </summary>
    /// <param name="services">The service collection to add the registration to.</param>
    /// <param name="consumer">The consumer's key, from <see cref="KeySetOwners"/>.</param>
    /// <param name="duration">Reads the consumer's lifetime out of the options. Resolved through a factory
    /// rather than captured here, so a host configuring options after this call is still honored.</param>
    private static void AddCachedSecureHttpFetcher(
        this IServiceCollection services,
        string consumer,
        Func<SecureHttpFetchOptions, TimeSpan> duration)
        => services.DecorateKeyed<ISecureHttpFetcher, CachingSecureHttpFetcherDecorator>(
            consumer,
            Dependency.Override(serviceProvider => duration(
                serviceProvider.GetRequiredService<IOptionsMonitor<SecureHttpFetchOptions>>().CurrentValue)));
}
