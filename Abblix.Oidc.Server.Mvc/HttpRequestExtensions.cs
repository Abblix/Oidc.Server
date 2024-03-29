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

using Microsoft.AspNetCore.Http;

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
}
