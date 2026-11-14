// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Mvc.Configuration;
using Microsoft.AspNetCore.Cors.Infrastructure;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Extension methods that turn <see cref="CorsSettings"/> into a CORS policy.
/// </summary>
public static class CorsOptionsExtensions
{
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
