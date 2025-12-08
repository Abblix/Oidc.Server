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

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

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
	/// <param name="request">The HTTP request used to access the <see cref="IUriResolver"/> service.</param>
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
	/// This extension method delegates to <see cref="IUriResolver.Content"/> for URI resolution.
	/// </remarks>
	public static Uri ToAbsoluteUri(this HttpRequest request, string path)
	{
		var uriResolver = request.HttpContext.RequestServices.GetRequiredService<IUriResolver>();
		return uriResolver.Content(path);
	}
}
