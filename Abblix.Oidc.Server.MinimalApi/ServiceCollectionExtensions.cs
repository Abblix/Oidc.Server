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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;
using Abblix.Oidc.Server.MinimalApi.Formatters;
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
    public static IServiceCollection AddOidcMinimalApi(
        this IServiceCollection services, Action<OidcOptions> configureOptions)
        => services.AddOidcMinimalApi((options, _) => configureOptions(options));

    /// <summary>
    /// Adds the OpenID Connect server (core plus the Minimal API transport) and configures its options with access
    /// to the service provider.
    /// </summary>
    /// <param name="services">The service collection to add the services to.</param>
    /// <param name="configureOptions">A delegate that configures the <see cref="OidcOptions"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> so calls can be chained.</returns>
    public static IServiceCollection AddOidcMinimalApi(
        this IServiceCollection services, Action<OidcOptions, IServiceProvider> configureOptions)
        => services
            .AddOidcCore(configureOptions)
            .AddOidcMinimalApi();

    /// <summary>
    /// Adds the Minimal API transport services for the OpenID Connect server. Assumes the core services
    /// (<c>AddOidcCore</c>) are registered separately.
    /// </summary>
    /// <param name="services">The service collection to add the services to.</param>
    /// <returns>The same <see cref="IServiceCollection"/> so calls can be chained.</returns>
    public static IServiceCollection AddOidcMinimalApi(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.AddOptions<OidcRouteOptions>();

        // The core resolves request details (base URL, scheme, client IP) through this contract; the adapter
        // supplies the ASP.NET Core HttpContext-backed implementation.
        services.TryAddSingleton<IRequestInfoProvider, HttpRequestInfoProvider>();

        // Flattens a response DTO into name/value pairs for query/fragment/form_post delivery.
        services.TryAddSingleton<IParametersProvider, Abblix.Oidc.Server.Common.ParametersProvider>();

        // Response formatters turn a core result into an IResult. TryAdd lets a host swap any of them.
        services.TryAddScoped<IConfigurationResultFormatter, ConfigurationResultFormatter>();

        services.TryAddScoped<ICheckSessionResultFormatter, CheckSessionResultFormatter>();
        services.Decorate<ICheckSessionResultFormatter, CheckSessionResultCachingDecorator>();
        services.TryAddSingleton<ICheckSessionResultCache, CheckSessionResultCache>();

        services.TryAddScoped<ITokenResultFormatter, TokenResultFormatter>();
        services.TryAddScoped<IRevocationResultFormatter, RevocationResultFormatter>();
        services.TryAddScoped<IIntrospectionResultFormatter, IntrospectionResultFormatter>();
        services.TryAddScoped<IPushedAuthorizationResultFormatter, PushedAuthorizationResultFormatter>();
        services.TryAddScoped<IBackChannelAuthenticationResultFormatter, BackChannelAuthenticationResultFormatter>();
        services.TryAddScoped<IDeviceAuthorizationResultFormatter, DeviceAuthorizationResultFormatter>();
        services.TryAddScoped<IUserInfoResultFormatter, UserInfoResultFormatter>();

        services.TryAddScoped<IEndSessionResultFormatter, EndSessionResultFormatter>();
        services.Decorate<IEndSessionResultFormatter, EndSessionResultDecorator>();

        services.TryAddScoped<IAuthorizationResultFormatter, AuthorizationResultFormatter>();

        services.TryAddScoped<RegistrationClientUriBuilder>();
        services.TryAddScoped<IRegisterClientResultFormatter, RegisterClientResultFormatter>();
        services.TryAddScoped<IReadClientResultFormatter, ReadClientResultFormatter>();
        services.TryAddScoped<IUpdateClientResultFormatter, UpdateClientResultFormatter>();
        services.TryAddScoped<IRemoveClientResultFormatter, RemoveClientResultFormatter>();

        // Results.Json serializes through Http.Json options (not MVC's), so the null-omission modifier the OIDC
        // wire format relies on is attached there. WithAddedModifier extends the resolver already in place rather
        // than chaining a new one, which would never be reached because the first resolver handles every type.
        services.Configure<JsonOptions>(options =>
        {
            options.SerializerOptions.TypeInfoResolver =
                (options.SerializerOptions.TypeInfoResolver ?? new DefaultJsonTypeInfoResolver())
                .WithAddedModifier(JsonIgnoreNullsModifier.Apply);
        });

        return services;
    }
}
