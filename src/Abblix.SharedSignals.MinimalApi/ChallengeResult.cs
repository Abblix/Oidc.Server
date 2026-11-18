// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// A status and one <c>WWW-Authenticate</c> line, with no body. The status is the caller's, not
/// this type's: any refusal whose explanation belongs in the challenge rather than in a payload
/// builds one of these, and its callers are what say which statuses those are.
/// Written by hand because <c>Results.Unauthorized()</c> emits no headers, and the header is the
/// whole point.
/// </summary>
internal sealed class ChallengeResult(int statusCode, string challenge) : IResult
{
    public Task ExecuteAsync(HttpContext httpContext)
    {
        httpContext.Response.StatusCode = statusCode;
        httpContext.Response.Headers.WWWAuthenticate = challenge;
        return Task.CompletedTask;
    }
}
