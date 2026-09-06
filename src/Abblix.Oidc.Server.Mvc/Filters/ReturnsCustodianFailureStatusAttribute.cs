// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using Abblix.Jwt.ExternalKeys;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Turns a failure of the external key custodian into a response the library chose. Without it the exception
/// escapes into the host, and what the caller receives is then whatever the host's environment does with an
/// unhandled exception: nothing at all in production, and the exception with its stack trace, naming the
/// custodian's key path, in a host running the developer diagnostics. The MVC counterpart of the Minimal API
/// adapter's <c>KeyCustodianFailureFilter</c>.
/// </summary>
/// <remarks>
/// The status carries the whole answer, because no registered OAuth error code describes a server that cannot
/// fulfil a valid request: the IANA registry lists <c>server_error</c> for the authorization endpoint alone, and
/// the codes RFC 6749 section 5.2 enumerates all say what was wrong with the request. So this maps to the two
/// HTTP statuses that already mean the two things a custodian failure can mean (RFC 9110 sections 15.6.1 and
/// 15.6.4): 503 for a custodian that is temporarily unable, carrying <c>Retry-After</c> when it named an
/// interval, and 500 for a failure that waiting will not resolve. Neither response derives a body from the
/// exception.
/// <para>
/// It recognises the library's own two custodian exceptions and nothing else, so an exception that never passed
/// through the custodian seam keeps travelling to whatever the host has around it. Applied as a controller
/// attribute for the same reason as its neighbour: it is pure controller metadata, mutating no global option, so
/// the OIDC endpoints and the host's own cannot clobber each other.
/// </para>
/// </remarks>
[AttributeUsage(AttributeTargets.Class, Inherited = true)]
internal sealed class ReturnsCustodianFailureStatusAttribute : Attribute, IExceptionFilter
{
	/// <inheritdoc />
	public void OnException(ExceptionContext context)
	{
		switch (context.Exception)
		{
			case KeyCustodianUnavailableException { RetryAfter: var retryAfter }:
				if (retryAfter is { } interval)
				{
					// Retry-After counts whole seconds (RFC 9110 section 10.2.3), and rounding up is what keeps
					// the advice honest: a client told to wait less than the custodian asked for arrives at the
					// same refusal.
					context.HttpContext.Response.Headers.RetryAfter =
						((long)Math.Ceiling(interval.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
				}

				context.Result = new StatusCodeResult(StatusCodes.Status503ServiceUnavailable);
				context.ExceptionHandled = true;
				break;

			case KeyCustodianFailedException:
				context.Result = new StatusCodeResult(StatusCodes.Status500InternalServerError);
				context.ExceptionHandled = true;
				break;
		}
	}
}
