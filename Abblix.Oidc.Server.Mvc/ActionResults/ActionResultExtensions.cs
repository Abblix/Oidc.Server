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

using System.Text;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using CookieOptions = Microsoft.AspNetCore.Http.CookieOptions;

namespace Abblix.Oidc.Server.Mvc.ActionResults;

/// <summary>
/// Composable post-processing helpers for <see cref="ActionResult"/> instances returned from OIDC controllers.
/// Each extension wraps the original result so it still executes its own pipeline, while attaching headers,
/// cookies, or formatting OAuth errors as RFC-compliant HTTP responses.
/// </summary>
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
	/// Pre-computed Cache-Control header value that combines multiple cache prevention directives
	/// for maximum compatibility across browsers, proxies, and HTTP versions.
	/// </summary>
	private static readonly CacheControlHeaderValue PreventStorageInAnyCache = new()
	{
		MaxAge = TimeSpan.Zero,
		SharedMaxAge = TimeSpan.Zero,
		NoStore = true,
		NoCache = true,
	};

	/// <summary>
	/// Sets comprehensive no-cache headers on the response to prevent caching.
	/// Ensures responses containing sensitive information (tokens, credentials, logout pages) are never cached.
	/// </summary>
	/// <remarks>
	/// Sets the following headers for maximum compatibility:
	/// <list type="bullet">
	/// <item><description>
	/// <b>Cache-Control</b>: "no-store, no-cache, max-age=0, s-maxage=0"
	/// - Prevents storage in any cache (HTTP/1.1)</description></item>
	/// <item><description>
	/// <b>Pragma</b>: "no-cache" - Prevents caching in HTTP/1.0 proxies and legacy browsers</description></item>
	/// <item><description>
	/// <b>Expires</b>: Unix epoch - Sets expiration to the past for HTTP/1.0 compatibility</description></item>
	/// </list>
	/// </remarks>
	/// <param name="response">The HTTP response to modify.</param>
	public static void SetNoCacheHeaders(this HttpResponse response)
	{
		var headers = response.GetTypedHeaders();
		headers.Expires = DateTimeOffset.UnixEpoch;
		headers.CacheControl = PreventStorageInAnyCache;
		response.Headers.Pragma = CacheControlHeaderValue.NoCacheString;
	}

	/// <summary>
	/// Decorates an <see cref="ActionResult"/> to prevent caching by appending comprehensive no-cache headers.
	/// </summary>
	/// <param name="innerResult">The <see cref="ActionResult"/> to decorate.</param>
	/// <returns>A decorated <see cref="ActionResult"/> with comprehensive cache prevention headers.</returns>
	public static ActionResult WithNoCacheHeaders(this ActionResult innerResult)
		=> new ActionResultDecorator(innerResult, SetNoCacheHeaders);

	/// <summary>
	/// Formats an <see cref="OidcError"/> as an appropriate HTTP error response per RFC 6750 Section 3.
	/// Bearer token errors (<c>invalid_token</c>) return HTTP 401 with only a <c>WWW-Authenticate</c> header
	/// and no response body. Scope errors (<c>insufficient_scope</c>) return HTTP 403 with the header.
	/// All other errors use the specified fallback status code with a JSON body.
	/// </summary>
	/// <param name="error">The OIDC error to format.</param>
	/// <param name="fallbackStatusCode">The HTTP status code to use for non-token errors.</param>
	/// <param name="realm">Optional realm value identifying the protection space (typically the issuer URI).</param>
	/// <returns>An <see cref="ActionResult"/> with the appropriate status code and headers.</returns>
	public static ActionResult Format(this OidcError error, int fallbackStatusCode, string? realm = null)
	{
		var challenge = FormatBearerChallenge(error, realm);

		return (error.Error, fallbackStatusCode) switch
		{
			(ErrorCodes.InvalidToken, _) => new UnauthorizedResult()
				.WithHeader(HeaderNames.WWWAuthenticate, challenge),

			(ErrorCodes.InsufficientScope, _) => new StatusCodeResult(StatusCodes.Status403Forbidden)
				.WithHeader(HeaderNames.WWWAuthenticate, challenge),

			(_, StatusCodes.Status400BadRequest)
				=> new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription)),

			(_, StatusCodes.Status401Unauthorized)
				=> new UnauthorizedObjectResult(new ErrorResponse(error.Error, error.ErrorDescription)),

			_ => new ObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))
				{ StatusCode = fallbackStatusCode },
		};
	}

	/// <summary>
	/// Builds a <c>WWW-Authenticate: Bearer</c> challenge value per RFC 6750 Section 3,
	/// including optional realm, error, and error_description attributes.
	/// </summary>
	private static string FormatBearerChallenge(OidcError error, string? realm)
	{
		var sb = new StringBuilder(TokenTypes.Bearer);
		var first = true;
		Append(sb, ref first, "realm", realm);
		Append(sb, ref first, "error", error.Error);
		Append(sb, ref first, "error_description", error.ErrorDescription);
		return sb.ToString();

		static void Append(StringBuilder sb, ref bool first, string name, string? value)
		{
			if (string.IsNullOrEmpty(value))
				return;

			sb.Append(first ? " " : ", ")
				.Append(name)
				.Append("=\"")
				.Append(value.Replace("\"", "'"))
				.Append('"');

			first = false;
		}
	}
}
