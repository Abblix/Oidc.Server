// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization.Metadata;
using Abblix.Oidc.Server.Mvc.Conventions;
using Abblix.Utils.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Extension methods that make the OIDC server's controllers part of the host's MVC application.
/// </summary>
public static class ControllerServiceCollectionExtensions
{
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
			.AddApplicationPart(typeof(ControllerServiceCollectionExtensions).Assembly);

		services.TryAddEnumerable(
			ServiceDescriptor.Singleton<IPostConfigureOptions<MvcOptions>, ConfigureEndpointConventions>());

		return services;
	}
}
