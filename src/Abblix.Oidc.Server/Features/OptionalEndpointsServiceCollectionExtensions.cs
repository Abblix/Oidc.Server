// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring
/// the opt-in token and client registration endpoints.
/// </summary>
public static class OptionalEndpointsServiceCollectionExtensions
{
    /// <summary>
    /// Opts the server into the OAuth 2.0 Token Revocation endpoint (RFC 7009). This single call registers the
    /// revocation handler, validator and processor and re-enables the <see cref="OidcEndpoints.Revocation"/>
    /// flag, which is off in the default <see cref="OidcOptions.EnabledEndpoints"/>. This governs only the public
    /// <c>/revoke</c> endpoint; the internal token-revocation machinery that refresh-token rotation, logout and
    /// initial-access-token invalidation depend on is always registered and is unaffected. A server that never
    /// calls this method exposes no revocation endpoint and does not advertise it in discovery.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddRevocation(this IServiceCollection services)
    {
        services.AddRevocationEndpoint();
        services.PostConfigure<OidcOptions>(options => options.EnabledEndpoints |= OidcEndpoints.Revocation);
        services.Configure<EndpointRegistrationMarker>(m => m.Registered |= OidcEndpoints.Revocation);
        return services;
    }

    /// <summary>
    /// Opts the server into the OAuth 2.0 Token Introspection endpoint (RFC 7662). This single call registers the
    /// introspection handler, validator and processor and re-enables the <see cref="OidcEndpoints.Introspection"/>
    /// flag, which is off in the default <see cref="OidcOptions.EnabledEndpoints"/>. Introspection is chiefly
    /// needed by resource servers validating opaque tokens; a server issuing self-contained JWTs often does not
    /// need it, so it is opt-in. A server that never calls this method exposes no introspection endpoint and does
    /// not advertise it in discovery.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddIntrospection(this IServiceCollection services)
    {
        services.AddIntrospectionEndpoint();
        services.PostConfigure<OidcOptions>(options => options.EnabledEndpoints |= OidcEndpoints.Introspection);
        services.Configure<EndpointRegistrationMarker>(m => m.Registered |= OidcEndpoints.Introspection);
        return services;
    }

    /// <summary>
    /// Opts the server into Dynamic Client Registration (RFC 7591 / RFC 7592). This single call registers the
    /// registration, read, update and remove handlers and their validators, and re-enables the
    /// <see cref="OidcEndpoints.RegisterClient"/> flag, which is off in the default
    /// <see cref="OidcOptions.EnabledEndpoints"/>. Open registration widens the attack surface, so it is opt-in:
    /// a server that never calls this method exposes no registration endpoint and does not advertise it in
    /// discovery. New-client defaults are taken from <see cref="OidcOptions.NewClientOptions"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddDynamicClientRegistration(this IServiceCollection services)
    {
        services.AddDynamicClientEndpoints(sp => sp.GetRequiredService<IOptions<OidcOptions>>().Value.NewClientOptions);
        services.PostConfigure<OidcOptions>(options => options.EnabledEndpoints |= OidcEndpoints.RegisterClient);
        services.Configure<EndpointRegistrationMarker>(m => m.Registered |= OidcEndpoints.RegisterClient);
        return services;
    }
}
