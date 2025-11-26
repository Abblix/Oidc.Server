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
