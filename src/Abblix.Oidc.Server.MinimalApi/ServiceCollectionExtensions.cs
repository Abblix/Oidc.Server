// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Text.Json.Serialization.Metadata;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.MinimalApi.Features.EndpointResolving;
using Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
using Abblix.Utils.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using JsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Extension methods that register the Abblix OpenID Connect server for ASP.NET Core Minimal APIs.
/// </summary>
/// <remarks>
/// This is the Minimal API counterpart of the MVC integration's <c>AddOidcServices</c>/<c>AddOidcMvc</c> pair.
/// The two adapters share the framework-neutral core (<c>AddOidcCore</c>) and differ only in the transport layer:
/// where the MVC package registers controllers, this package maps route handlers through
/// <see cref="EndpointRouteBuilderExtensions.MapOidcEndpoints(Microsoft.AspNetCore.Routing.IEndpointRouteBuilder, string)"/>.
/// </remarks>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the OpenID Connect server (core plus the Minimal API transport) and configures its options.
    /// </summary>
    /// <param name="services">The service collection to add the services to.</param>
    /// <param name="configureOptions">A delegate that configures the <see cref="OidcOptions"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> so calls can be chained.</returns>
    /// <remarks>
    /// Named exactly as the MVC integration names it, so moving a host from one adapter to the other leaves
    /// this line alone: what changes is the package reference and the endpoint mapping, not the registration.
    /// </remarks>
    public static IServiceCollection AddOidcServices(
        this IServiceCollection services, Action<OidcOptions> configureOptions)
        => services.AddOidcServices((options, _) => configureOptions(options));

    /// <summary>
    /// Adds the OpenID Connect server (core plus the Minimal API transport) and configures its options with access
    /// to the service provider.
    /// </summary>
    /// <param name="services">The service collection to add the services to.</param>
    /// <param name="configureOptions">A delegate that configures the <see cref="OidcOptions"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> so calls can be chained.</returns>
    public static IServiceCollection AddOidcServices(
        this IServiceCollection services, Action<OidcOptions, IServiceProvider> configureOptions)
        => services
            .AddOidcCore(configureOptions)
            .AddOidcMinimalApi();

    /// <summary>
    /// Adds the Minimal API transport services for the OpenID Connect server. Assumes the core services
    /// (<c>AddOidcCore</c>) are registered separately. The counterpart of the MVC integration's
    /// <c>AddOidcMvc()</c>.
    /// </summary>
    /// <param name="services">The service collection to add the services to.</param>
    /// <returns>The same <see cref="IServiceCollection"/> so calls can be chained.</returns>
    public static IServiceCollection AddOidcMinimalApi(this IServiceCollection services)
    {
        // Both adapters registered means both will serve the OIDC endpoints, and the host finds out only when
        // a request arrives and routing reports an ambiguity that names neither package. Caught here it names
        // the call to remove. The counterpart check in MapOidcEndpoints looks for the MVC assembly instead,
        // because a host can carry the package without ever calling its registration - and that is enough for
        // AddControllers() to map its controllers.
        TransportAdapterConflict.ThrowIfRegistered(
            services,
            TransportAdapterConflict.MvcAdapterAssemblyName,
            "Both OIDC transport adapters are registered in this application: the Minimal API adapter was " +
            "added after the MVC adapter's own AddOidcServices()/AddOidcMvc(). Only one of them may serve " +
            "the OIDC endpoints - with both in place they claim the same paths and every OIDC request fails " +
            "with AmbiguousMatchException. Keep one: remove either the MVC registration together with the " +
            "Abblix.OIDC.Server.MVC package reference, or this one together with the " +
            "Abblix.OIDC.Server.MinimalApi package reference.");

        services.AddHttpContextAccessor();
        services.AddOptions<OidcRouteOptions>();

        // The core resolves request details (base URL, scheme, client IP) through this contract; the adapter
        // supplies the ASP.NET Core HttpContext-backed implementation.
        services.TryAddSingleton<IRequestInfoProvider, HttpRequestInfoProvider>();

        // Absolute URLs for the OIDC endpoints, under the contract the MVC adapter answers too, so host code
        // that needs one survives a change of adapter unchanged.
        services.TryAddScoped<IOidcEndpointResolver, OidcEndpointResolver>();

        // The default authentication-session bridge over the host's cookie authentication scheme,
        // mirroring the MVC transport. TryAdd lets a host supply its own session service instead.
        services.TryAddScoped<IAuthSessionService, AuthenticationSchemeAdapter>();

        // Flattens a response DTO into name/value pairs for query/fragment/form_post delivery.
        services.TryAddSingleton<IParametersProvider, Abblix.Oidc.Server.Common.ParametersProvider>();

        // Response formatters turn a core result into an IResult. TryAdd lets a host swap any of them.
        services.TryAddScoped<IConfigurationResponseFormatter, ConfigurationResponseFormatter>();

        services.TryAddScoped<ICheckSessionResponseFormatter, CheckSessionResponseFormatter>();
        services.Decorate<ICheckSessionResponseFormatter, CheckSessionResponseCachingDecorator>();
        services.TryAddSingleton<ICheckSessionResponseCache, CheckSessionResponseCache>();

        services.TryAddScoped<ITokenResponseFormatter, TokenResponseFormatter>();
        services.TryAddScoped<IRevocationResponseFormatter, RevocationResponseFormatter>();
        services.TryAddScoped<IIntrospectionResponseFormatter, IntrospectionResponseFormatter>();
        services.TryAddScoped<IPushedAuthorizationResponseFormatter, PushedAuthorizationResponseFormatter>();
        services.TryAddScoped<IBackChannelAuthenticationResponseFormatter, BackChannelAuthenticationResponseFormatter>();
        services.TryAddScoped<IDeviceAuthorizationResponseFormatter, DeviceAuthorizationResponseFormatter>();
        services.TryAddScoped<IUserInfoResponseFormatter, UserInfoResponseFormatter>();

        services.TryAddScoped<IEndSessionResponseFormatter, EndSessionResponseFormatter>();
        services.Decorate<IEndSessionResponseFormatter, EndSessionResponseFormatterDecorator>();

        services.TryAddScoped<IAuthorizationResponseFormatter, AuthorizationResponseFormatter>();

        services.TryAddScoped<RegistrationClientUriBuilder>();
        services.TryAddScoped<IRegisterClientResponseFormatter, RegisterClientResponseFormatter>();
        services.TryAddScoped<IReadClientResponseFormatter, ReadClientResponseFormatter>();
        services.TryAddScoped<IUpdateClientResponseFormatter, UpdateClientResponseFormatter>();
        services.TryAddScoped<IRemoveClientResponseFormatter, RemoveClientResponseFormatter>();

        // Results.Json serializes through Http.Json options (not MVC's), so the null-omission modifier the OIDC
        // wire format relies on is attached there. WithAddedModifier extends the resolver already in place rather
        // than chaining a new one, which would never be reached because the first resolver handles every type.
        services.Configure<JsonOptions>(options =>
        {
            options.SerializerOptions.TypeInfoResolver =
                (options.SerializerOptions.TypeInfoResolver ?? new DefaultJsonTypeInfoResolver())
                .WithAddedModifier(JsonIgnoreNullsModifier.Apply);
        });

        // Every OIDC endpoint is tagged with RequireCors(OidcConstants.CorsPolicyName). The MVC host inherited
        // CORS services from AddControllersWithViews; AddOidcCors gives the Minimal API host the same reach and
        // the shared, host-overridable default policy the endpoints require, so app.UseCors() no longer throws
        // for missing services. See AddOidcCors for the supplement/override contract.
        services.AddOidcCors();

        return services;
    }
}
