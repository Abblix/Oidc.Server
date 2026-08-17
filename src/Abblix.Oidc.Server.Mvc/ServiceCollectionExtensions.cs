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

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Mvc.Binders;
using Abblix.Oidc.Server.Mvc.Configuration;
using Abblix.Oidc.Server.Mvc.Conventions;
using Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;
using Abblix.Oidc.Server.Mvc.Features.EndpointResolving;
using Abblix.Oidc.Server.Mvc.Features.SessionManagement;
using Abblix.Oidc.Server.Mvc.Formatters;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils.Json;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System.Text.Json.Serialization.Metadata;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Extension methods for adding OpenID Connect (OIDC) server services to the <see cref="IServiceCollection"/>.
/// These methods simplify the integration of OIDC server capabilities into an ASP.NET Core application,
/// allowing for the configuration of OIDC options and services necessary for authentication and authorization.
/// </summary>
public static class ServiceCollectionExtensions
{
	/// <summary>
	/// Adds OIDC server services to the specified <see cref="IServiceCollection"/> with provided configuration options.
	/// This method allows for configuring OIDC options to tailor the authentication server to your specific needs.
	/// </summary>
	/// <remarks>
	/// The request pipeline must call <c>app.UseCors()</c> after <c>app.UseRouting()</c>. The protocol
	/// controllers carry CORS metadata, because browser-based clients read the discovery document, the
	/// key set and the token endpoint cross-origin - and ASP.NET Core routing refuses to serve any
	/// endpoint whose CORS metadata no middleware honours, so without that call every protocol endpoint
	/// answers 500. The policy itself is registered here; only the middleware call belongs to the host,
	/// since the framework accepts the middleware only when it runs after routing has selected an
	/// endpoint - a place no library can insert it from.
	/// </remarks>
	/// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
	/// <param name="configureOptions">A delegate to configure the <see cref="OidcOptions"/>.</param>
	/// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
	public static IServiceCollection AddOidcServices(this IServiceCollection services, Action<OidcOptions> configureOptions)
	{
		return services.AddOidcServices((options, _) => configureOptions(options));
	}

	/// <summary>
	/// Adds OIDC server services to the specified <see cref="IServiceCollection"/> with provided configuration options and service provider.
	/// </summary>
	/// <remarks>
	/// The request pipeline must call <c>app.UseCors()</c> after <c>app.UseRouting()</c>; see the
	/// remarks on <see cref="AddOidcServices(IServiceCollection, Action{OidcOptions})"/> for why the
	/// protocol endpoints refuse to answer without it.
	/// </remarks>
	/// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
	/// <param name="configureOptions">A delegate to configure the <see cref="OidcOptions"/> with the service provider.</param>
	/// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
	public static IServiceCollection AddOidcServices(this IServiceCollection services, Action<OidcOptions, IServiceProvider> configureOptions)
	{
		return services
			.AddOidcCore(configureOptions)
			.AddOidcMvc();
	}

	/// <summary>
	/// Adds OIDC MVC services to the specified <see cref="IServiceCollection"/>.
	/// This method sets up MVC services required for handling OIDC endpoints and requests within an ASP.NET Core application.
	/// </summary>
	/// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
	/// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    public static IServiceCollection AddOidcMvc(
        this IServiceCollection services)
    {
		// Both adapters registered means both will serve the OIDC endpoints, and the host finds out only when
		// a request arrives and routing reports an ambiguity that names neither package. Caught here it names
		// the call to remove. Only the registration is checked on this side: the presence of the Minimal API
		// package maps nothing on its own, so it is the call, not the reference, that creates the conflict.
		TransportAdapterConflict.ThrowIfRegistered(
			services,
			TransportAdapterConflict.MinimalApiAdapterAssemblyName,
			"Both OIDC transport adapters are registered in this application: the MVC adapter was added " +
			"after the Minimal API adapter's own AddOidcServices()/AddOidcMinimalApi(). Only one of them may " +
			"serve the OIDC endpoints - with both in place they claim the same paths and every OIDC request " +
			"fails with AmbiguousMatchException. Keep one: remove either the Minimal API registration " +
			"together with the Abblix.OIDC.Server.MinimalApi package reference, or this one together with " +
			"the Abblix.OIDC.Server.MVC package reference.");

		services
			.AddOidcControllers()
			.ConfigureRoutesFallback()
			.AddHttpContextAccessor();

		services.TryAddSingleton<IParameterValidator, ParameterValidator>();
		services.TryAddSingleton<IParametersProvider, Abblix.Oidc.Server.Common.ParametersProvider>();
		services.TryAddSingleton<IRequestInfoProvider, HttpRequestInfoProvider>();
		services.TryAddScoped<IAuthSessionService, AuthenticationSchemeAdapter>();
		services.TryAddSingleton<IUriResolver, UriResolver>();
		services.TryAddScoped<IEndpointResolver, EndpointResolver>();

		// Absolute URLs for the OIDC endpoints, under the contract the Minimal API adapter answers too, so
		// host code that needs one survives a change of adapter unchanged.
		services.TryAddScoped<IOidcEndpointResolver, Features.EndpointResolving.OidcEndpointResolver>();
		services.TryAddSingleton<IUrlHelperFactory, UrlHelperFactory>();
		services.TryAddScoped<IConfigurationResponseFormatter, ConfigurationResponseFormatter>();
		services.TryAddScoped<IAuthorizationResponseFormatter, AuthorizationResponseFormatter>();
		services.TryAddScoped<IPushedAuthorizationResponseFormatter, PushedAuthorizationResponseFormatter>();
		services.TryAddScoped<ITokenResponseFormatter, TokenResponseFormatter>();
		services.TryAddScoped<IUserInfoResponseFormatter, UserInfoResponseFormatter>();

		services.TryAddScoped<IEndSessionResponseFormatter, EndSessionResponseFormatter>();
		services.Decorate<IEndSessionResponseFormatter, EndSessionResponseFormatterDecorator>();

		services.TryAddScoped<IRevocationResponseFormatter, RevocationResponseFormatter>();
		services.TryAddScoped<IIntrospectionResponseFormatter, IntrospectionResponseFormatter>();
		services.TryAddScoped<IBackChannelAuthenticationResponseFormatter, BackChannelAuthenticationResponseFormatter>();
		services.TryAddScoped<IDeviceAuthorizationResponseFormatter, DeviceAuthorizationResponseFormatter>();

		services.TryAddScoped<ICheckSessionResponseFormatter, CheckSessionResponseFormatter>();
		services.Decorate<ICheckSessionResponseFormatter, CheckSessionResponseCachingDecorator>();
		services.TryAddSingleton<ICheckSessionResponseCache, CheckSessionResponseCache>();

		services.TryAddScoped<IRegisterClientResponseFormatter, RegisterClientResponseFormatter>();
		services.TryAddScoped<IReadClientResponseFormatter, ReadClientResponseFormatter>();
		services.TryAddScoped<IUpdateClientResponseFormatter, UpdateClientResponseFormatter>();
		services.TryAddScoped<IRemoveClientResponseFormatter, RemoveClientResponseFormatter>();

		services.Configure<MvcOptions>(options =>
		{
			options.OutputFormatters.Add(new StringOutputFormatter());
			options.ModelBinderProviders.Insert(0, new CultureInfoBinder());
			options.ModelMetadataDetailsProviders.Add(new RequiredBindingMetadataProvider());
		});

		// AddOidcCors registers the shared, host-overridable default so the CORS policy the controllers
		// reference with [EnableCors] resolves out of the box instead of only when the host defined it. Same
		// policy and supplement/override contract as the Minimal API adapter. See AddOidcCors.
		services.AddOidcCors();

	    return services;
    }

	/// <summary>
	/// Adds OIDC controllers to the MVC application. This method is used internally to ensure that the OIDC server's
	/// controllers are available to handle authentication and authorization requests.
	/// </summary>
	/// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
	/// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    public static IServiceCollection AddOidcControllers(this IServiceCollection services)
    {
        services
            .AddControllers()
            .AddApplicationPart(typeof(ServiceCollectionExtensions).Assembly)
            .AddControllersAsServices();

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPostConfigureOptions<MvcOptions>, ConfigureEndpointConventions>());

        services
            .PostConfigure<JsonOptions>(options =>
            {
                // WithAddedModifier attaches to the resolver already in place (set up by AddControllers),
                // so the modifier runs within that resolver rather than in a separate chained one.
                // A chained resolver would never be reached because the default resolver handles all types first.
                options.JsonSerializerOptions.TypeInfoResolver =
                    (options.JsonSerializerOptions.TypeInfoResolver ?? new DefaultJsonTypeInfoResolver())
                    .WithAddedModifier(JsonIgnoreNullsModifier.Apply);
            });

        return services;
    }

	/// <summary>
	/// Configures the application's CORS policy according to the specified <see cref="CorsSettings"/>.
	/// This method enables the customization of CORS policies for OIDC endpoints, allowing for the specification
	/// of allowed origins, methods, and headers, as well as whether credentials are supported.
	/// </summary>
	/// <param name="options">The <see cref="CorsOptions"/> to configure.</param>
	/// <param name="policyName">The name of the CORS policy, used to identify it.</param>
	/// <param name="settings">The <see cref="CorsSettings"/> that define the CORS policy.</param>
	public static void AppPolicy(this CorsOptions options, string policyName, CorsSettings settings)
    {
	    options.AddPolicy(policyName, policy =>
	    {
		    settings.AllowedOrigins.ApplyTo(policy.AllowAnyOrigin, policy.WithOrigins);
		    settings.AllowedMethods.ApplyTo(policy.AllowAnyMethod, policy.WithMethods);
		    settings.AllowedHeaders.ApplyTo(policy.AllowAnyHeader, policy.WithHeaders);

		    if (settings.ExposeHeaders != null)
			    policy.WithExposedHeaders(settings.ExposeHeaders);

		    switch (settings.AllowCredentials)
		    {
			    case true:
				    policy.AllowCredentials();
				    break;

			    case false:
				    policy.DisallowCredentials();
				    break;
		    }

		    if (settings.MaxAge.HasValue)
			    policy.SetPreflightMaxAge(settings.MaxAge.Value);
	    });
    }

	/// <summary>
	/// Applies configuration based on the specified values to a <see cref="CorsPolicyBuilder"/>.
	/// This method dynamically configures CORS policies based on the provided values. If a wildcard "*" is provided,
	/// it configures the policy to allow any value (origin, method, or header). Otherwise, it applies the specific
	/// values provided. This allows for flexible configuration of CORS policies.
	/// </summary>
	/// <param name="values">The array of values to be applied. Can be origins, methods, or headers.</param>
	/// <param name="allowAnyValues">A function that configures the policy to allow any values for the setting.</param>
	/// <param name="withValues">A function that applies specific values to the policy.</param>
	private static void ApplyTo(
		this string[]? values,
		Func<CorsPolicyBuilder> allowAnyValues,
		Func<string[], CorsPolicyBuilder> withValues)
	{
		switch (values)
		{
			case null:
				break;

			case ["*"]:
				allowAnyValues();
				break;

			default:
				withValues(values);
				break;
		}
	}
}
