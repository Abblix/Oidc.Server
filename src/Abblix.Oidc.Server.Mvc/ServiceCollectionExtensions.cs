// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Mvc.Binders;
using Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;
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
			.AddHttpContextAccessor()
			.AddOidcMvcInfrastructure()
			.AddOidcProtocolFormatters()
			.AddOidcInteractionFormatters();

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
}
