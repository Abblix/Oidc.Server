// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// The sign-in page the server sends the end user to, with the client the pending authorization request is for.
/// </summary>
/// <remarks>
/// The suite's registration modules ask the reviewer to confirm the page shows the logo, policy and terms the client
/// registered, and the browser driver checks for them by id.
/// </remarks>
public static class LoginPage
{
    /// <summary>The page, as HTML.</summary>
    /// <param name="requestUri">The pending authorization request the form carries back.</param>
    /// <param name="error">Why the previous attempt was refused, or null.</param>
    /// <param name="client">The client the pending request is for, or null when it is not known.</param>
    public static string Render(string requestUri, string? error, ClientInfo? client)
    {
        var errorBlock = error == null ? "" : $"<p id=\"error\">{WebUtility.HtmlEncode(error)}</p>";
        var clientBlock = new StringBuilder();
        if (client is { ClientName: { } name })
            clientBlock.Append($"<p id=\"client-name\">{WebUtility.HtmlEncode(name)}</p>");
        if (client is { LogoUri: { } logo })
            clientBlock.Append($"<p><img id=\"client-logo\" src=\"{WebUtility.HtmlEncode(logo.OriginalString)}\" alt=\"Client logo\" /></p>");
        if (client is { PolicyUri: { } policy })
            clientBlock.Append($"<p><a id=\"client-policy\" href=\"{WebUtility.HtmlEncode(policy.OriginalString)}\">Privacy policy</a></p>");
        if (client is { TermsOfServiceUri: { } terms })
            clientBlock.Append($"<p><a id=\"client-tos\" href=\"{WebUtility.HtmlEncode(terms.OriginalString)}\">Terms of service</a></p>");

        return $"""
            <!DOCTYPE html>
            <html>
            <head><title>Conformance host</title></head>
            <body>
                <h1>Sign in</h1>
                {clientBlock}
                {errorBlock}
                <form method="post" action="/login">
                    <input type="hidden" name="requestUri" value="{WebUtility.HtmlEncode(requestUri)}" />
                    <p><label>Email: <input type="email" name="email" autofocus /></label></p>
                    <p><label>Password: <input type="password" name="password" /></label></p>
                    <button type="submit" id="sign-in" name="action" value="allow">Sign in</button>
                    <button type="submit" id="deny" name="action" value="deny">Sign in and refuse</button>
                </form>
            </body>
            </html>
            """;
    }
}
