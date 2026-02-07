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
    private class CheckSessionHtmlResult(string htmlTemplate) : ActionResult
    {
        public override Task ExecuteResultAsync(ActionContext context)
        {
            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(NonceByteLength));
            var htmlContent = htmlTemplate.Replace(NoncePlaceholder, nonce);

            var response = context.HttpContext.Response;
            response.StatusCode = StatusCodes.Status200OK;
            response.ContentType = MediaTypeNames.Text.Html;
            response.Headers["Content-Security-Policy"] = $"default-src 'none'; script-src 'nonce-{nonce}'";

            return response.WriteAsync(htmlContent);
        }
    }
}
