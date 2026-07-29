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

using System.Net.Mime;
using System.Security.Cryptography;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Microsoft.AspNetCore.Http;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Produces the check-session iframe document, generating a per-request CSP nonce to protect the inline script.
/// </summary>
public class CheckSessionResponseFormatter : ICheckSessionResponseFormatter
{
    private const string NoncePlaceholder = "{{nonce}}";
    private const int NonceByteLength = 16;

    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(CheckSessionResponse response)
        => Task.FromResult<IResult>(new CheckSessionHtmlResult(response.HtmlContent));

    /// <summary>
    /// An <see cref="IResult"/> that generates a fresh CSP nonce on each execution, injects it into the HTML template,
    /// and sets the Content-Security-Policy header. The result itself carries only the template, so it stays safe to
    /// cache while still producing a unique nonce per request.
    /// </summary>
    private sealed class CheckSessionHtmlResult(string htmlTemplate) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(NonceByteLength));
            var htmlContent = htmlTemplate.Replace(NoncePlaceholder, nonce);

            var response = httpContext.Response;
            response.StatusCode = StatusCodes.Status200OK;
            response.ContentType = MediaTypeNames.Text.Html;
            response.Headers.ContentSecurityPolicy = $"default-src 'none'; script-src 'nonce-{nonce}'";

            // The token is the request's own: a browser that navigates away mid-write aborts the
            // request, and without it the write goes on against a connection nobody is reading.
            return response.WriteAsync(htmlContent, httpContext.RequestAborted);
        }
    }
}
