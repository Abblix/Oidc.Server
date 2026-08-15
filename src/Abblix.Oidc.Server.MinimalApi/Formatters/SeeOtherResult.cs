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

using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Redirects the user agent with HTTP 303 See Other instead of the framework-default 302 Found.
/// A 303 forces the follow-up request to use GET and never re-sends the original request body, so the
/// authorization endpoint (which accepts POST and may carry the user's credentials) never leaks that body
/// to the redirect target. This is why the OAuth 2.0 Security Best Current Practice mandates 303 here and
/// forbids the body-preserving 307 (RFC 9700, Section 4.12).
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
