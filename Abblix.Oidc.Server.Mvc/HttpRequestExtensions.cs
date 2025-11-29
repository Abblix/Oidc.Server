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

using Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Provides extension methods for the <see cref="HttpRequest"/> class.
/// These methods are used to retrieve various URL components from an HTTP request.
/// </summary>
public static class HttpRequestExtensions
{
	/// <summary>
	/// Gets the application's base URL from the HTTP request.
	/// This includes the scheme, host, and the base path of the application.
	/// </summary>
	/// <param name="request">The HTTP request.</param>
	/// <returns>The application's base URL.</returns>
	public static string GetAppUrl(this HttpRequest request) => request.GetFullUrl(request.PathBase);

	/// <summary>
	/// Gets the base URL of the request.
	/// This includes the scheme, host, and the path of the request.
	/// </summary>
	/// <param name="request">The HTTP request.</param>
	/// <returns>The base URL of the request.</returns>
	public static string GetBaseUrl(this HttpRequest request) => request.GetFullUrl(request.Path);

	/// <summary>
	/// Constructs a full URL from the request's components and the specified path.
	/// </summary>
	/// <param name="request">The HTTP request.</param>
	/// <param name="path">The path to append to the base URL.</param>
	/// <returns>The full URL constructed from the request's components and the specified path.</returns>
	private static string GetFullUrl(this HttpRequest request, PathString path)
		=> request.Scheme + Uri.SchemeDelimiter + request.Host + path;

	/// <summary>
	/// Converts a relative path into an absolute URI using the application's base URL.
	/// </summary>
	/// <param name="request">The HTTP request used to determine the application's base URL.</param>
	/// <param name="path">
	/// The path to resolve. Supports:
	/// - Application-relative paths starting with <c>"~/"</c> (e.g., <c>~/dashboard</c>)
	/// - Route template constants with default values (e.g., <c>[route:authorize?~/connect/authorize]</c>)
	/// - Regular relative paths
	/// </param>
	/// <returns>
	/// A fully qualified <see cref="Uri"/> representing the resolved absolute URL.
	/// </returns>
	/// <remarks>
	/// This method resolves route template constants from <see cref="Path"/> class using the current
	/// routing configuration. If route values are configured, they override the default values.
	/// </remarks>
	public static Uri ToAbsoluteUri(this HttpRequest request, string path)
	{
		var appUrl = request.GetAppUrl();

		// Handle route template constants like [route:authorize?~/connect/authorize]
		path = request.ResolveRouteTemplate(path);

		return path.StartsWith("~/")
			? new Uri(appUrl + path[1..], UriKind.Absolute)
			: new Uri(new Uri(appUrl, UriKind.Absolute), path);
	}

	/// <summary>
	/// Resolves route template constants to their actual path values using the registered
	/// <see cref="ConfigurableRouteConvention"/> from MVC options.
	/// This ensures the same configuration is used for both route templates and runtime path resolution.
	/// </summary>
	/// <param name="request">The HTTP request providing access to services.</param>
	/// <param name="path">The path that may contain route template syntax.</param>
	/// <returns>The resolved path with route templates replaced by actual values.</returns>
	private static string ResolveRouteTemplate(this HttpRequest request, string path)
	{
		// Try to get the registered ConfigurableRouteConvention from MVC options
		var mvcOptions = request.HttpContext.RequestServices.GetService<IOptions<MvcOptions>>();

		// If convention is registered, use it to resolve the path
		var convention = mvcOptions?.Value.Conventions
			.OfType<ConfigurableRouteConvention>()
			.FirstOrDefault();

		// Fallback: create a convention with no configuration section (uses only fallback values)
		convention ??= new ConfigurableRouteConvention();

		return convention.Resolve(path);
	}
}
