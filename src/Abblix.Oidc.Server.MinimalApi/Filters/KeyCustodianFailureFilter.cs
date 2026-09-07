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

namespace Abblix.Oidc.Server.MinimalApi.Filters;

/// <summary>
/// A group-scoped endpoint filter that turns a failure of the external key custodian into a response the library
/// chose. Without it the exception escapes into the host, and what the caller receives is then whatever the host's
/// environment does with an unhandled exception: nothing at all in production, and the exception with its stack
/// trace, naming the custodian's key path, in a host running the developer diagnostics.
/// </summary>
/// <remarks>
/// The status carries the whole answer, because no registered OAuth error code describes a server that cannot
/// fulfill a valid request: the IANA registry lists <c>server_error</c> for the authorization endpoint only, and
/// the codes RFC 6749 section 5.2 enumerates all say what was wrong with the request. So this maps to the two
/// HTTP statuses that already mean the two things a custodian failure can mean (RFC 9110 sections 15.6.1 and
/// 15.6.4): 503 for a custodian that is temporarily unable, carrying <c>Retry-After</c> when it named an
/// interval, and 500 for a failure that waiting will not resolve. Neither response derives a body from the
/// exception.
/// <para>
/// It recognizes the library's own two custodian exceptions and nothing else. Catching more would swallow
/// unrelated defects into a bare 500 and take that decision away from hosts that already have error handling of
/// their own, which is a far larger change than this one. The log line lives at the custodian seam instead of
/// here, where the custodian's own answer is still in hand.
/// </para>
/// </remarks>
internal sealed class KeyCustodianFailureFilter : IEndpointFilter
{
    /// <inheritdoc />
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            return await next(context);
        }
        catch (KeyCustodianUnavailableException exception)
        {
            if (exception.RetryAfter is { } retryAfter)
            {
                // Retry-After counts whole seconds (RFC 9110 section 10.2.3), and rounding up is what keeps the
                // advice honest: a client told to wait less than the custodian asked for arrives to the same
                // refusal.
                context.HttpContext.Response.Headers.RetryAfter =
                    ((long)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
            }

            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
        catch (KeyCustodianFailedException)
        {
            return Results.StatusCode(StatusCodes.Status500InternalServerError);
        }
    }
}
