// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using System.Threading.RateLimiting;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Introspection;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Endpoints.Revocation;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Features.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.Telemetry;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the revocation and introspection endpoints and the per-caller budget both of them spend.
/// </summary>
internal static class TokenLifecycleServiceCollectionExtensions
{
    /// <summary>
    /// Adds services for validating and processing revocation requests. This capability is essential for OAuth 2.0
    /// compliance, enabling clients to revoke access or refresh tokens when they are no longer needed or if
    /// a security issue arises, thus minimizing the potential for unauthorized use of tokens.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddRevocationEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<IRevocationHandler, RevocationHandler>();
        services.Decorate<IRevocationHandler, TracedRevocationHandler>();
        services.TryAddScoped<IRevocationRequestValidator, RevocationRequestValidator>();
        services.TryAddScoped<IRevocationRequestProcessor, RevocationRequestProcessor>();
        services.AddCallerRateLimiter(CallerRateLimiters.Revocation);
        services.TryAddSingleton<UnnamedSourceNotice>();
        return services;
    }

    /// <summary>
    /// Adds validators and processors for introspection requests, enabling resource servers to verify the active status
    /// of tokens and access token metadata. This feature is crucial for applications that need to validate tokens
    /// coming from different clients or issued by external authorization servers.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddIntrospectionEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<IIntrospectionHandler, IntrospectionHandler>();
        services.Decorate<IIntrospectionHandler, TracedIntrospectionHandler>();
        services.TryAddScoped<IIntrospectionRequestValidator, IntrospectionRequestValidator>();
        services.TryAddScoped<IIntrospectionRequestProcessor, IntrospectionRequestProcessor>();
        services.AddCallerRateLimiter(CallerRateLimiters.Introspection);
        return services;
    }

    /// <summary>
    /// Registers the per-caller budget one endpoint spends, under the given key, and the startup check on the
    /// numbers it is built from.
    /// </summary>
    /// <remarks>
    /// Registered with <c>TryAdd</c>, so a host that put its own limiter under this key before calling this
    /// library keeps it: the endpoint then spends whatever policy that limiter implements, and the settings here
    /// decide nothing. The startup check on them still runs: it is one validator for the whole options type and
    /// cannot see which keys a host pre-empted, so a deployment that has finished with these numbers takes them
    /// out of its configuration rather than leaving a value nothing reads.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <param name="key">The key the endpoint resolves its limiter by, from <see cref="CallerRateLimiters"/>.</param>
    private static void AddCallerRateLimiter(this IServiceCollection services, string key)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, CallerRateLimitOptionsValidator>());

        services.TryAddKeyedSingleton<PartitionedRateLimiter<(string ClientId, string? Source)>>(
            key,
            (serviceProvider, _) => CallerRateLimiters.Create(
                serviceProvider.GetRequiredService<IOptions<OidcOptions>>().Value.CallerRateLimit));
    }
}
