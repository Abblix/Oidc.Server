// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// MVC-only <see cref="HttpRequest"/> extension that resolves an application-relative path to an absolute URI
/// through the MVC <see cref="IUriResolver"/>. The framework-neutral URL helpers (<c>GetAppUrl</c>/<c>GetBaseUrl</c>)
/// live in the shared <c>Abblix.Oidc.Server.AspNetCore</c> project.
/// </summary>
public static class HttpRequestExtensions
{
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
