// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc.Routing;
using static Microsoft.AspNetCore.Http.HttpMethods;



namespace Abblix.Oidc.Server.Mvc.Attributes;

/// <summary>
/// Specifies that an action supports both HTTP GET and POST methods.
/// </summary>
/// <remarks>
/// This attribute can be applied to an action method to indicate that it should
/// respond to HTTP GET and POST requests. When applied to an action method, it specifies
/// that the method handles requests made with these two HTTP methods. It can be used to
/// support scenarios where a resource can be fetched (GET) or submitted (POST) to the same URL.
/// </remarks>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public class HttpGetOrPostAttribute : HttpMethodAttribute
{
	private static readonly IEnumerable<string> SupportedMethods = [Get, Post];

	/// <summary>
	/// Initializes a new instance of the <see cref="HttpGetOrPostAttribute"/> class without specifying a route template.
	/// </summary>
	public HttpGetOrPostAttribute()
		: base(SupportedMethods)
	{
	}

	/// <summary>
	/// Initializes a new instance of the <see cref="HttpGetOrPostAttribute"/> class with the specified route template.
	/// </summary>
	/// <param name="template">The route template. The template may define path segments, parameters, etc., as per routing conventions.</param>
	public HttpGetOrPostAttribute(string template)
		: base(SupportedMethods, template)
	{
	}
}
