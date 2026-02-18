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

using System.Text;
using System.Text.RegularExpressions;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Mvc.Formatters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Formatters;

/// <summary>
/// Unit tests for <see cref="CheckSessionResponseFormatter"/> verifying Content Security Policy
/// header generation and nonce handling for the check_session_iframe.
/// </summary>
public partial class CheckSessionResponseFormatterTests
{
    private const string CookieName = "test_session";
    private const string NoncePlaceholder = "{{nonce}}";

    /// <summary>
    /// Verifies that executing the formatted result sets a Content-Security-Policy header.
    /// CSP is required to protect the check session iframe from XSS attacks.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_WhenExecuted_SetsCspHeader()
    {
        // Arrange
        var formatter = new CheckSessionResponseFormatter();
        var response = CreateCheckSessionResponse();
        var actionResult = await formatter.FormatResponseAsync(response);
        var context = CreateActionContext();

        // Act
        await actionResult.ExecuteResultAsync(context);

        // Assert
        Assert.True(context.HttpContext.Response.Headers.ContainsKey("Content-Security-Policy"));
    }

    /// <summary>
    /// Verifies that CSP header contains default-src 'none' directive.
    /// This denies all resources by default, requiring explicit allowlisting.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_CspContainsDefaultSrcNone()
    {
        // Arrange
        var formatter = new CheckSessionResponseFormatter();
        var response = CreateCheckSessionResponse();
        var actionResult = await formatter.FormatResponseAsync(response);
        var context = CreateActionContext();

        // Act
        await actionResult.ExecuteResultAsync(context);

        // Assert
        var csp = context.HttpContext.Response.Headers["Content-Security-Policy"].ToString();
        Assert.Contains("default-src 'none'", csp);
    }

    /// <summary>
    /// Verifies that CSP header contains script-src with nonce.
    /// Nonce allows the inline script while blocking all other scripts.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_CspContainsScriptSrcWithNonce()
    {
        // Arrange
        var formatter = new CheckSessionResponseFormatter();
        var response = CreateCheckSessionResponse();
        var actionResult = await formatter.FormatResponseAsync(response);
        var context = CreateActionContext();

        // Act
        await actionResult.ExecuteResultAsync(context);

        // Assert
        var csp = context.HttpContext.Response.Headers["Content-Security-Policy"].ToString();
        Assert.Matches(ScriptSrcNoncePattern(), csp);
    }

    /// <summary>
    /// Verifies that nonce in CSP matches nonce in HTML script tag.
    /// Mismatch would cause the browser to block the script.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_NonceInCspMatchesNonceInHtml()
    {
        // Arrange
        var htmlTemplate = $"<script nonce=\"{NoncePlaceholder}\">console.log('test');</script>";
        var formatter = new CheckSessionResponseFormatter();
        var response = new CheckSessionResponse(htmlTemplate, CookieName);
        var actionResult = await formatter.FormatResponseAsync(response);
        var context = CreateActionContext();

        // Act
        await actionResult.ExecuteResultAsync(context);

        // Assert
        var csp = context.HttpContext.Response.Headers["Content-Security-Policy"].ToString();
        var html = GetResponseBody(context);

        var cspNonceMatch = Regex.Match(csp, @"'nonce-([A-Za-z0-9+/=]+)'");
        var htmlNonceMatch = Regex.Match(html, @"nonce=""([A-Za-z0-9+/=]+)""");

        Assert.True(cspNonceMatch.Success, "CSP should contain nonce");
        Assert.True(htmlNonceMatch.Success, "HTML should contain nonce");
        Assert.Equal(cspNonceMatch.Groups[1].Value, htmlNonceMatch.Groups[1].Value);
    }

    /// <summary>
    /// Verifies that different executions of the same ActionResult produce different nonces.
    /// Nonce must be unique per request for security.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_GeneratesUniqueNoncePerExecution()
    {
        // Arrange
        var formatter = new CheckSessionResponseFormatter();
        var response = CreateCheckSessionResponse();
        var actionResult = await formatter.FormatResponseAsync(response);
        var context1 = CreateActionContext();
        var context2 = CreateActionContext();

        // Act
        await actionResult.ExecuteResultAsync(context1);
        await actionResult.ExecuteResultAsync(context2);

        // Assert
        var csp1 = context1.HttpContext.Response.Headers["Content-Security-Policy"].ToString();
        var csp2 = context2.HttpContext.Response.Headers["Content-Security-Policy"].ToString();

        var nonce1 = Regex.Match(csp1, @"'nonce-([A-Za-z0-9+/=]+)'").Groups[1].Value;
        var nonce2 = Regex.Match(csp2, @"'nonce-([A-Za-z0-9+/=]+)'").Groups[1].Value;

        Assert.NotEqual(nonce1, nonce2);
    }

    /// <summary>
    /// Verifies that the nonce placeholder is replaced in HTML content.
    /// The {{nonce}} placeholder must be replaced with actual nonce value.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_ReplacesNoncePlaceholder()
    {
        // Arrange
        var htmlTemplate = $"<script nonce=\"{NoncePlaceholder}\">test</script>";
        var formatter = new CheckSessionResponseFormatter();
        var response = new CheckSessionResponse(htmlTemplate, CookieName);
        var actionResult = await formatter.FormatResponseAsync(response);
        var context = CreateActionContext();

        // Act
        await actionResult.ExecuteResultAsync(context);

        // Assert
        var html = GetResponseBody(context);
        Assert.DoesNotContain(NoncePlaceholder, html);
    }

    /// <summary>
    /// Verifies that nonce is base64-encoded.
    /// Base64 encoding is required for CSP nonce values.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_NonceIsBase64Encoded()
    {
        // Arrange
        var formatter = new CheckSessionResponseFormatter();
        var response = CreateCheckSessionResponse();
        var actionResult = await formatter.FormatResponseAsync(response);
        var context = CreateActionContext();

        // Act
        await actionResult.ExecuteResultAsync(context);

        // Assert
        var csp = context.HttpContext.Response.Headers["Content-Security-Policy"].ToString();
        var nonceMatch = Regex.Match(csp, @"'nonce-([A-Za-z0-9+/=]+)'");
        Assert.True(nonceMatch.Success);

        var nonce = nonceMatch.Groups[1].Value;
        // Verify it's valid base64 by attempting to decode
        var bytes = Convert.FromBase64String(nonce);
        Assert.Equal(16, bytes.Length); // 16 bytes = 128 bits of randomness
    }

    /// <summary>
    /// Verifies that the same ActionResult can be executed multiple times.
    /// This confirms caching compatibility - the ActionResult acts as a template.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_ActionResultIsReusable()
    {
        // Arrange
        var formatter = new CheckSessionResponseFormatter();
        var response = CreateCheckSessionResponse();
        var actionResult = await formatter.FormatResponseAsync(response);

        // Act - Execute same result multiple times
        var context1 = CreateActionContext();
        var context2 = CreateActionContext();
        var context3 = CreateActionContext();

        await actionResult.ExecuteResultAsync(context1);
        await actionResult.ExecuteResultAsync(context2);
        await actionResult.ExecuteResultAsync(context3);

        // Assert - All should succeed with different nonces
        Assert.Equal(200, context1.HttpContext.Response.StatusCode);
        Assert.Equal(200, context2.HttpContext.Response.StatusCode);
        Assert.Equal(200, context3.HttpContext.Response.StatusCode);

        var nonce1 = ExtractNonceFromCsp(context1);
        var nonce2 = ExtractNonceFromCsp(context2);
        var nonce3 = ExtractNonceFromCsp(context3);

        Assert.NotEqual(nonce1, nonce2);
        Assert.NotEqual(nonce2, nonce3);
        Assert.NotEqual(nonce1, nonce3);
    }

    /// <summary>
    /// Verifies that response has status code 200 OK.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_SetsStatusCode200()
    {
        // Arrange
        var formatter = new CheckSessionResponseFormatter();
        var response = CreateCheckSessionResponse();
        var actionResult = await formatter.FormatResponseAsync(response);
        var context = CreateActionContext();

        // Act
        await actionResult.ExecuteResultAsync(context);

        // Assert
        Assert.Equal(200, context.HttpContext.Response.StatusCode);
    }

    /// <summary>
    /// Verifies that response has content type text/html.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_SetsContentTypeHtml()
    {
        // Arrange
        var formatter = new CheckSessionResponseFormatter();
        var response = CreateCheckSessionResponse();
        var actionResult = await formatter.FormatResponseAsync(response);
        var context = CreateActionContext();

        // Act
        await actionResult.ExecuteResultAsync(context);

        // Assert
        Assert.Equal("text/html", context.HttpContext.Response.ContentType);
    }

    /// <summary>
    /// Verifies that HTML content is written to response body.
    /// </summary>
    [Fact]
    public async Task FormatResponseAsync_WritesHtmlToBody()
    {
        // Arrange
        var htmlTemplate = "<!DOCTYPE html><html><body>Test</body></html>";
        var formatter = new CheckSessionResponseFormatter();
        var response = new CheckSessionResponse(htmlTemplate, CookieName);
        var actionResult = await formatter.FormatResponseAsync(response);
        var context = CreateActionContext();

        // Act
        await actionResult.ExecuteResultAsync(context);

        // Assert
        var html = GetResponseBody(context);
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("Test", html);
    }

    private static CheckSessionResponse CreateCheckSessionResponse()
    {
        var htmlTemplate = $@"<!DOCTYPE html>
<html>
<head>
    <script nonce=""{NoncePlaceholder}"">console.log('session check');</script>
</head>
<body></body>
</html>";
        return new CheckSessionResponse(htmlTemplate, CookieName);
    }

    private static ActionContext CreateActionContext()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Response.Body = new MemoryStream();
        return new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
    }

    private static string GetResponseBody(ActionContext context)
    {
        context.HttpContext.Response.Body.Position = 0;
        using var reader = new StreamReader(context.HttpContext.Response.Body, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static string ExtractNonceFromCsp(ActionContext context)
    {
        var csp = context.HttpContext.Response.Headers["Content-Security-Policy"].ToString();
        var match = Regex.Match(csp, @"'nonce-([A-Za-z0-9+/=]+)'");
        return match.Success ? match.Groups[1].Value : string.Empty;
    }

    [GeneratedRegex(@"script-src 'nonce-[A-Za-z0-9+/=]+'")]
    private static partial Regex ScriptSrcNoncePattern();
}
