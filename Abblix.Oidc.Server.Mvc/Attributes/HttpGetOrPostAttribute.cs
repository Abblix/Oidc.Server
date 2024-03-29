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
	private static readonly IEnumerable<string> SupportedMethods = new[] { Get, Post };

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
