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

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Turns an OAuth/OIDC error into an <see cref="IResult"/> and decorates results with headers, mirroring the MVC
/// integration's <c>ActionResultExtensions</c> so both adapters emit identical HTTP error shapes.
/// </summary>
public static class OidcResults
{
    /// <summary>
    /// Formats an <see cref="OidcError"/> as an HTTP error response per RFC 6750 §3 / RFC 6749 §5.2:
    /// <c>invalid_token</c> returns 401 with a <c>WWW-Authenticate</c> Bearer challenge and no body;
    /// <c>insufficient_scope</c> returns 403 with the header; <c>invalid_client</c> returns 401 with a Basic challenge
    /// and the JSON error body; everything else uses the fallback status code with a JSON body.
    /// </summary>
    public static IResult Format(this OidcError error, int fallbackStatusCode, string? realm = null)
    {
        var challenge = WwwAuthenticateBuilder.BuildBearerChallenge(error, realm);

        return (error.Error, fallbackStatusCode) switch
        {
            (ErrorCodes.InvalidToken, _) => Results
                .StatusCode(StatusCodes.Status401Unauthorized)
                .WithHeader(HeaderNames.WWWAuthenticate, challenge),

            (ErrorCodes.InsufficientScope, _) => Results
                .StatusCode(StatusCodes.Status403Forbidden)
                .WithHeader(HeaderNames.WWWAuthenticate, challenge),

            // RFC 6749 §5.2: a 401 with a Basic challenge for a client-authentication failure; the error stays in the
            // JSON body because RFC 7617 defines no error attributes for the Basic scheme.
            (ErrorCodes.InvalidClient, _) => Results
                .Json(new ErrorResponse(error.Error, error.ErrorDescription), statusCode: StatusCodes.Status401Unauthorized)
                .WithHeader(HeaderNames.WWWAuthenticate, WwwAuthenticateBuilder.BuildBasicChallenge(realm)),

            (_, StatusCodes.Status400BadRequest) => Results
                .Json(new ErrorResponse(error.Error, error.ErrorDescription), statusCode: StatusCodes.Status400BadRequest),

            (_, StatusCodes.Status401Unauthorized) => Results
                .Json(new ErrorResponse(error.Error, error.ErrorDescription), statusCode: StatusCodes.Status401Unauthorized),

            _ => Results.Json(new ErrorResponse(error.Error, error.ErrorDescription), statusCode: fallbackStatusCode),
        };
    }

    /// <summary>
    /// Formats an <see cref="OidcError"/> as an HTTP error response that advertises the DPoP scheme (RFC 9449 §7.1) on
    /// the <c>WWW-Authenticate</c> header, optionally alongside Bearer. <see cref="UseDPoPNonceError"/> additionally
    /// emits the <c>DPoP-Nonce</c> header so the client can echo the freshly issued nonce on retry.
    /// </summary>
    public static IResult Format(
        this OidcError error,
        int fallbackStatusCode,
        string? realm,
        IEnumerable<string> dpopAlgs,
        bool advertiseBearer)
    {
        var challenges = WwwAuthenticateBuilder.BuildChallenges(error, realm, dpopAlgs, advertiseBearer);

        var result = error switch
        {
            InvalidDPoPProofError or UseDPoPNonceError or { Error: ErrorCodes.InvalidToken }
                => Results.StatusCode(StatusCodes.Status401Unauthorized),

            { Error: ErrorCodes.InsufficientScope }
                => Results.StatusCode(StatusCodes.Status403Forbidden),

            _ when fallbackStatusCode == StatusCodes.Status400BadRequest
                => Results.Json(new ErrorResponse(error.Error, error.ErrorDescription),
                    statusCode: StatusCodes.Status400BadRequest),

            _ when fallbackStatusCode == StatusCodes.Status401Unauthorized
                => Results.Json(new ErrorResponse(error.Error, error.ErrorDescription),
                    statusCode: StatusCodes.Status401Unauthorized),

            _ => Results.Json(new ErrorResponse(error.Error, error.ErrorDescription), statusCode: fallbackStatusCode),
        };

        result = result.WithHeader(HeaderNames.WWWAuthenticate, challenges);

        if (error is UseDPoPNonceError { Nonce: var nonce })
            result = result.WithHeader(HttpRequestHeaders.DPoPNonce, nonce);

        return result;
    }

    /// <summary>Decorates a result to set a response header before the inner result executes.</summary>
    public static IResult WithHeader(this IResult inner, string name, string value)
        => new ResultDecorator(inner, response => response.Headers[name] = value);

    /// <summary>Decorates a result to append each value as a separate header line under the same name.</summary>
    public static IResult WithHeader(this IResult inner, string name, IEnumerable<string> values)
        => new ResultDecorator(inner, response =>
        {
            foreach (var value in values)
                response.Headers.Append(name, value);
        });

    /// <summary>
    /// Decorates a self-rendered HTML result (the form_post auto-submit page) with the anti-framing headers so it
    /// can never be embedded in another origin's frame (clickjacking defense, RFC 9700 Section 4.16). The check_session
    /// page cannot use this path: its CSP carries a per-request nonce generated inside the result, so it sets the
    /// header itself.
    /// </summary>
    public static IResult WithAntiFramingHeaders(this IResult inner)
        => inner
            .WithHeader(HeaderNames.ContentSecurityPolicy, AntiFramingHeaders.ContentSecurityPolicy)
            .WithHeader(HeaderNames.XFrameOptions, AntiFramingHeaders.XFrameOptions);

    /// <summary>Decorates a result to append a cookie to the response before the inner result executes.</summary>
    public static IResult WithAppendCookie(
        this IResult inner, string name, string value, Microsoft.AspNetCore.Http.CookieOptions options)
        => new ResultDecorator(inner, response => response.Cookies.Append(name, value, options));

    /// <summary>Decorates a result to delete a cookie from the response before the inner result executes.</summary>
    public static IResult WithDeleteCookie(
        this IResult inner, string name, Microsoft.AspNetCore.Http.CookieOptions options)
        => new ResultDecorator(inner, response => response.Cookies.Delete(name, options));

    /// <summary>
    /// Wraps an inner <see cref="IResult"/> and applies a mutation to the response (headers, cookies) before the inner
    /// result writes the status and body.
    /// </summary>
    private sealed class ResultDecorator(IResult inner, Action<HttpResponse> decorate) : IResult
    {
        public async Task ExecuteAsync(HttpContext httpContext)
        {
            decorate(httpContext.Response);
            await inner.ExecuteAsync(httpContext);
        }
    }
}
