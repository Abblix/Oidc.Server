// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Mvc.Features.EndpointResolving;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Registers how the MVC transport reads a request, answers the session, and builds the URLs it hands out.
/// </summary>
internal static class MvcInfrastructureRegistration
{
	public static IServiceCollection AddOidcMvcInfrastructure(this IServiceCollection services)
	{
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
		return services;
	}
}
