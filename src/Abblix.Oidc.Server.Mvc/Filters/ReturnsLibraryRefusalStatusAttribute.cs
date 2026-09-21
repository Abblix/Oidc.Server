// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Turns a refusal the library decides for itself into a response the library chose - a key custodian that
/// cannot answer, a source whose failed authentications are over budget. Without it such an exception escapes
/// into the host, and what the caller receives is then whatever the host's environment does with an unhandled
/// exception: nothing at all in production, and the exception with its stack trace, naming the custodian's key
/// path, in a host running the developer diagnostics. The MVC counterpart of the Minimal API adapter's
/// <c>LibraryRefusalFilter</c>.
/// </summary>
/// <remarks>
/// The status carries the whole answer, because no registered OAuth error code describes a server that cannot
/// fulfill a valid request, or a caller that has asked too often: the IANA registry lists <c>server_error</c> for
/// the authorization endpoint alone, and the codes RFC 6749 section 5.2 enumerates all say what was wrong with the
/// request. So each refusal maps to the HTTP status that already means it (RFC 9110 sections 15.6.1 and 15.6.4):
/// 503 for a custodian that is temporarily unable, 500 for a failure that waiting will not resolve, and 429 for
/// a source over its budget. The two that pass with an interval carry <c>Retry-After</c>. No response derives a
/// body from the exception.
/// <para>
/// It recognizes the library's own refusals and nothing else, so an exception that never passed through one of
/// those seams keeps traveling to whatever the host has around it. Applied as a controller attribute for the
/// same reason as its neighbor: it is pure controller metadata, mutating no global option, so the OIDC
/// endpoints and the host's own cannot clobber each other.
/// </para>
/// </remarks>
[AttributeUsage(AttributeTargets.Class, Inherited = true)]
internal sealed class ReturnsLibraryRefusalStatusAttribute : Attribute, IExceptionFilter
{
	/// <inheritdoc />
	public void OnException(ExceptionContext context)
	{
		switch (context.Exception)
		{
			case KeyCustodianUnavailableException { RetryAfter: var retryAfter }:
				if (retryAfter is { } interval)
				{
					context.HttpContext.Response.SetRetryAfter(interval);
				}

				context.Result = new StatusCodeResult(StatusCodes.Status503ServiceUnavailable);
				context.ExceptionHandled = true;
				break;

			case KeyCustodianFailedException:
				context.Result = new StatusCodeResult(StatusCodes.Status500InternalServerError);
				context.ExceptionHandled = true;
				break;

			case TooManyAuthenticationFailuresException { RetryAfter: var retryAfter }:
				if (retryAfter is { } wait)
				{
					context.HttpContext.Response.SetRetryAfter(wait);
				}

				context.Result = new StatusCodeResult(StatusCodes.Status429TooManyRequests);
				context.ExceptionHandled = true;
				break;
		}
	}
}
