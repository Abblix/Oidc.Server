// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Mime;
using System.Security.Cryptography;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for Check Session frames, generating a per-request CSP nonce
/// to protect the inline script from XSS attacks.
/// </summary>
public class CheckSessionResponseFormatter : ICheckSessionResponseFormatter
{
    private const string NoncePlaceholder = "{{nonce}}";
    private const int NonceByteLength = 16;

    /// <summary>
    /// Formats a response for a Check Session frame asynchronously.
    /// </summary>
    /// <param name="response">The Check Session response containing HTML content.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation,
    /// with the formatted response as an <see cref="ActionResult"/>.</returns>
    public Task<ActionResult> FormatResponseAsync(CheckSessionResponse response)
        => Task.FromResult<ActionResult>(new CheckSessionHtmlResult(response.HtmlContent));

    /// <summary>
    /// An ActionResult that generates a fresh CSP nonce on each execution,
    /// injects it into the HTML template, and sets the Content-Security-Policy header.
    /// This allows the ActionResult to be cached while still producing unique nonces per request.
    /// </summary>
    private sealed class CheckSessionHtmlResult(string htmlTemplate) : ActionResult
    {
        public override Task ExecuteResultAsync(ActionContext context)
        {
            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(NonceByteLength));
            var htmlContent = htmlTemplate.Replace(NoncePlaceholder, nonce);

            var response = context.HttpContext.Response;
            response.StatusCode = StatusCodes.Status200OK;
            response.ContentType = MediaTypeNames.Text.Html;
            response.Headers.ContentSecurityPolicy = $"default-src 'none'; script-src 'nonce-{nonce}'";

            // The token is the request's own: a browser that navigates away mid-write aborts the
            // request, and without it the write goes on against a connection nobody is reading.
            return response.WriteAsync(htmlContent, context.HttpContext.RequestAborted);
        }
    }
}
