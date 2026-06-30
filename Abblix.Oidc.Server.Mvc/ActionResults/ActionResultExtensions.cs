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
	/// Decorates an <see cref="ActionResult"/> to append each value as a separate header line.
	/// Use when the wire form expects multiple header lines under the same name (e.g. RFC 9449
	/// §7.1 dual <c>WWW-Authenticate</c> emission for DPoP and Bearer); plain
	/// <see cref="WithHeader"/> overwrites instead of appending.
	/// </summary>
	public static ActionResult WithAppendHeader(
		this ActionResult innerResult,
		string name,
		IEnumerable<string> values)
		=> new ActionResultDecorator(
			innerResult,
			response =>
			{
				foreach (var value in values)
					response.Headers.Append(name, value);
			});

	/// <summary>
	/// Formats an <see cref="OidcError"/> as an appropriate HTTP error response per RFC 6750 Section 3.
	/// Bearer token errors (<c>invalid_token</c>) return HTTP 401 with only a <c>WWW-Authenticate</c> header
	/// and no response body. Scope errors (<c>insufficient_scope</c>) return HTTP 403 with the header.
	/// Client authentication failures (<c>invalid_client</c>) return HTTP 401 with a Basic challenge
	/// and the JSON error body per RFC 6749 Section 5.2.
	/// All other errors use the specified fallback status code with a JSON body.
	/// </summary>
	/// <param name="error">The OIDC error to format.</param>
	/// <param name="fallbackStatusCode">The HTTP status code to use for non-token errors.</param>
	/// <param name="realm">Optional realm value identifying the protection space (typically the issuer URI).</param>
	/// <returns>An <see cref="ActionResult"/> with the appropriate status code and headers.</returns>
	public static ActionResult Format(this OidcError error, int fallbackStatusCode, string? realm = null)
	{
		var challenge = WwwAuthenticateBuilder.BuildBearerChallenge(error, realm);

		return (error.Error, fallbackStatusCode) switch
		{
			(ErrorCodes.InvalidToken, _) => new UnauthorizedResult()
				.WithHeader(HeaderNames.WWWAuthenticate, challenge),

			(ErrorCodes.InsufficientScope, _) => new StatusCodeResult(StatusCodes.Status403Forbidden)
				.WithHeader(HeaderNames.WWWAuthenticate, challenge),

			// RFC 6749 §5.2: a 401 is REQUIRED when the client authenticated via the Authorization
			// header and allowed otherwise, so the uniform 401 satisfies both cases. Basic is the
			// only Authorization-header scheme the client-authenticating endpoints (token,
			// introspection, revocation) support, hence the Basic challenge; the error itself stays
			// in the JSON body because RFC 7617 defines no error attributes for the Basic scheme.
			(ErrorCodes.InvalidClient, _)
				=> new UnauthorizedObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))
					.WithHeader(HeaderNames.WWWAuthenticate, WwwAuthenticateBuilder.BuildBasicChallenge(realm)),

			(_, StatusCodes.Status400BadRequest)
				=> new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription)),

			(_, StatusCodes.Status401Unauthorized)
				=> new UnauthorizedObjectResult(new ErrorResponse(error.Error, error.ErrorDescription)),

			_ => new ObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))
				{ StatusCode = fallbackStatusCode },
		};
	}

	/// <summary>
	/// Formats an <see cref="OidcError"/> as an HTTP error response that advertises the DPoP
	/// scheme (RFC 9449 §7.1) on the <c>WWW-Authenticate</c> header, optionally alongside the
	/// Bearer scheme. <see cref="UseDPoPNonceError"/> additionally emits the <c>DPoP-Nonce</c>
	/// response header so the client can echo the freshly issued nonce on retry.
	/// </summary>
	public static ActionResult Format(
		this OidcError error,
		int fallbackStatusCode,
		string? realm,
		IEnumerable<string> dpopAlgs,
		bool advertiseBearer)
	{
		var challenges = WwwAuthenticateBuilder.BuildChallenges(error, realm, dpopAlgs, advertiseBearer);

		ActionResult result = error switch
		{
			InvalidDPoPProofError or UseDPoPNonceError or { Error: ErrorCodes.InvalidToken } => new UnauthorizedResult(),
			{ Error: ErrorCodes.InsufficientScope } => new StatusCodeResult(StatusCodes.Status403Forbidden),

			_ when fallbackStatusCode == StatusCodes.Status400BadRequest
				=> new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription)),

			_ when fallbackStatusCode == StatusCodes.Status401Unauthorized
				=> new UnauthorizedObjectResult(new ErrorResponse(error.Error, error.ErrorDescription)),

			_ => new ObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))
				{ StatusCode = fallbackStatusCode },
		};

		result = result.WithAppendHeader(HeaderNames.WWWAuthenticate, challenges);

		if (error is UseDPoPNonceError { Nonce: var nonce })
			result = result.WithHeader(HttpRequestHeaders.DPoPNonce, nonce);

		return result;
	}
}
