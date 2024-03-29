// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Mvc.Binders;
using Abblix.Oidc.Server.Mvc.Configuration;
using Abblix.Oidc.Server.Mvc.Features.SessionManagement;
using Abblix.Oidc.Server.Mvc.Formatters;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.DependencyInjection;

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
		services
			.AddOidcControllers()
			.AddHttpContextAccessor()

		    .AddSingleton<IParameterValidator, ParameterValidator>()
			.AddSingleton<IParametersProvider, ParametersProvider>()
		    .AddSingleton<IRequestInfoProvider, HttpRequestInfoAdapter>()
			.AddSingleton<IAuthenticationService, AuthenticationSchemeAdapter>()
			.AddSingleton<IUriResolver, UriResolver>()
			.AddSingleton<IActionContextAccessor, ActionContextAccessor>()
			.AddSingleton<IUrlHelperFactory, UrlHelperFactory>()
			.AddScoped<IAuthorizationResponseFormatter, AuthorizationResponseFormatter>()
			.AddScoped<IPushedAuthorizationResponseFormatter, PushedAuthorizationResponseFormatter>()
			.AddScoped<ITokenResponseFormatter, TokenResponseFormatter>()
			.AddScoped<IUserInfoResponseFormatter, UserInfoResponseFormatter>()

			.AddScoped<IEndSessionResponseFormatter, EndSessionResponseFormatter>()
			.Decorate<IEndSessionResponseFormatter, EndSessionResponseFormatterDecorator>()

			.AddScoped<IRevocationResponseFormatter, RevocationResponseFormatter>()
			.AddScoped<IIntrospectionResponseFormatter, IntrospectionResponseFormatter>()
			.AddScoped<IBackChannelAuthenticationResponseFormatter, BackChannelAuthenticationResponseFormatter>()

			.AddScoped<ICheckSessionResponseFormatter, CheckSessionResponseFormatter>()
			.Decorate<ICheckSessionResponseFormatter, CheckSessionResponseCachingDecorator>()
			.AddSingleton<ICheckSessionResponseCache, CheckSessionResponseCache>()

			.AddScoped<IRegisterClientResponseFormatter, RegisterClientResponseFormatter>()
			.AddScoped<IReadClientResponseFormatter, ReadClientResponseFormatter>()
			.AddScoped<IRemoveClientResponseFormatter, RemoveClientResponseFormatter>()

			.Configure<MvcOptions>(options =>
			{
				options.OutputFormatters.Add(new StringOutputFormatter());
				options.ModelBinderProviders.Insert(0, new CultureInfoBinder());
				options.ModelMetadataDetailsProviders.Add(new RequiredBindingMetadataProvider());
			});

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
        return services
            .AddControllers()
            .AddApplicationPart(typeof(ServiceCollectionExtensions).Assembly)
            .AddControllersAsServices()
            .Services;
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
		if (values == null)
			return;

		if (values.Length == 1 && values[0] == "*")
			allowAnyValues();
		else
			withValues(values);
	}
}
