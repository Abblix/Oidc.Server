// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Redirects the user agent with HTTP 303 See Other instead of the framework-default 302 Found.
/// A 303 forces the follow-up request to use GET and never re-sends the original request body, so the
/// authorization endpoint (which accepts POST and may carry the user's credentials) never leaks that body
/// to the redirect target. RFC 9700 Section 4.12 says such a server "MUST NOT use the HTTP 307" and
/// "SHOULD use HTTP status code 303 (See Other)": 307 is forbidden, and 303 is the recommended choice.
/// </summary>
internal sealed class SeeOtherResult : IResult
{
    private readonly string _location;

    /// <summary>
    /// Initializes a new instance of the <see cref="SeeOtherResult"/> class.
    /// </summary>
    /// <param name="location">The absolute URI to redirect the user agent to.</param>
    public SeeOtherResult(string location) => _location = location;

    /// <inheritdoc />
    public Task ExecuteAsync(HttpContext httpContext)
    {
        var response = httpContext.Response;
        response.StatusCode = StatusCodes.Status303SeeOther;
        response.Headers.Location = _location;
        return Task.CompletedTask;
    }
}
