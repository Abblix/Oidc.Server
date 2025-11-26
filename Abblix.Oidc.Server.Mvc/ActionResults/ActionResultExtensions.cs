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

using Abblix.Oidc.Server.Common.Constants;
using Microsoft.AspNetCore.Mvc;
using CookieOptions = Microsoft.AspNetCore.Http.CookieOptions;

namespace Abblix.Oidc.Server.Mvc.ActionResults;

public static class ActionResultExtensions
{
	/// <summary>
	/// Decorates an <see cref="ActionResult"/> to append a cookie to the response.
	/// </summary>
	/// <param name="innerResult">The <see cref="ActionResult"/> to decorate.</param>
	/// <param name="name">The name of the cookie to append.</param>
	/// <param name="value">The value of the cookie.</param>
	/// <param name="options">The <see cref="CookieOptions"/> to configure the cookie.</param>
	/// <returns>A decorated <see cref="ActionResult"/> that appends the specified cookie.</returns>
	public static ActionResult WithAppendCookie(this ActionResult innerResult, string name, string value, CookieOptions options)
		=> new ActionResultDecorator(innerResult, response => response.Cookies.Append(name, value, options));

	/// <summary>
	/// Decorates an <see cref="ActionResult"/> to delete a cookie from the response.
	/// </summary>
	/// <param name="innerResult">The <see cref="ActionResult"/> to decorate.</param>
	/// <param name="name">The name of the cookie to delete.</param>
	/// <param name="options">The <see cref="CookieOptions"/> to configure the deletion of the cookie.</param>
	/// <returns>A decorated <see cref="ActionResult"/> that deletes the specified cookie.</returns>
	public static ActionResult WithDeleteCookie(this ActionResult innerResult, string name, CookieOptions options)
		=> new ActionResultDecorator(innerResult, response => response.Cookies.Delete(name, options));

	/// <summary>
	/// Decorates an <see cref="ActionResult"/> to append a header to the response.
	/// </summary>
	/// <param name="innerResult">The <see cref="ActionResult"/> to decorate.</param>
	/// <param name="name">The name of the header to append.</param>
	/// <param name="value">The value of the header.</param>
	/// <returns>A decorated <see cref="ActionResult"/> that appends the specified header.</returns>
	public static ActionResult WithHeader(this ActionResult innerResult, string name, string value)
		=> new ActionResultDecorator(innerResult, response => response.Headers[name] = value);

	/// <summary>
	/// Decorates an <see cref="ActionResult"/> to prevent caching by appending standard no-cache headers.
	/// Appends 'Cache-Control: no-store' and 'Pragma: no-cache' headers as required by
	/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">OpenID Connect Core specification</see>.
	/// </summary>
	/// <param name="innerResult">The <see cref="ActionResult"/> to decorate.</param>
	/// <returns>A decorated <see cref="ActionResult"/> with cache prevention headers.</returns>
	public static ActionResult WithNoCacheHeaders(this ActionResult innerResult)
		=> innerResult
			.WithHeader(HttpResponseHeaders.CacheControl, HttpResponseHeaders.CacheControlValues.NoStore)
			.WithHeader(HttpResponseHeaders.Pragma, HttpResponseHeaders.PragmaValues.NoCache);
}
