// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Filters;

/// <summary>
/// A group-scoped endpoint filter that turns a refusal the library decides for itself - a key custodian that
/// cannot answer, a source whose failed authentications are over budget - into a response the library chose.
/// Without it the exception escapes into the host, and what the caller receives is then whatever the host's
/// environment does with an unhandled exception: nothing at all in production, and the exception with its stack
/// trace, naming the custodian's key path, in a host running the developer diagnostics. The Minimal API
/// counterpart of the MVC adapter's <c>ReturnsLibraryRefusalStatusAttribute</c>.
/// </summary>
/// <remarks>
/// The status carries the whole answer, because no registered OAuth error code describes a server that cannot
/// fulfill a valid request, or a caller that has asked too often: the IANA registry lists <c>server_error</c> for
/// the authorization endpoint only, and the codes RFC 6749 section 5.2 enumerates all say what was wrong with the
/// request. So each refusal maps to the HTTP status that already means it (RFC 9110 sections 15.6.1 and 15.6.4):
/// 503 for a custodian that is temporarily unable, 500 for a failure that waiting will not resolve, and 429 for
/// a source over its budget. The two that pass with an interval carry <c>Retry-After</c>. No response derives a
/// body from the exception.
/// <para>
/// It recognizes the library's own refusals and nothing else. Catching more would swallow unrelated defects
/// into a bare 500 and take that decision away from hosts that already have error handling of their own, which
/// is a far larger change than this one. Each log line lives at the seam that decided the refusal instead of
/// here, where what that seam knew is still in hand.
/// </para>
/// </remarks>
internal sealed class LibraryRefusalFilter : IEndpointFilter
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
                context.HttpContext.Response.SetRetryAfter(retryAfter);
            }

            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
        catch (KeyCustodianFailedException)
        {
            return Results.StatusCode(StatusCodes.Status500InternalServerError);
        }
        catch (TooManyAuthenticationFailuresException exception)
        {
            if (exception.RetryAfter is { } retryAfter)
            {
                context.HttpContext.Response.SetRetryAfter(retryAfter);
            }

            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }
    }
}
