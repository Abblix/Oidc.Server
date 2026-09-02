// Abblix OIDC Client Library
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

using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.SessionManagement;

/// <summary>
/// Builds the frame that watches whether the end-user is still logged in at the provider.
/// </summary>
/// <param name="options">How often to ask.</param>
public sealed class SessionCheckFrameBuilder(IOptions<SessionCheckOptions> options)
    : ISessionCheckFrameBuilder
{
    private const string ResourceName =
        "Abblix.Oidc.Client.Features.SessionManagement.Resources.sessionCheckFrame.html";

    private static readonly string Template = ReadTemplate();

    /// <inheritdoc />
    public SessionCheckFrame Build(SessionCheck check, Uri selfOrigin)
    {
        if (!Uri.TryCreate(check.CheckSessionIframe, UriKind.Absolute, out var checkSessionIframe))
        {
            throw new SessionCheckException(
                $"The provider published '{check.CheckSessionIframe}' as its session-management frame, "
                + "which is not an absolute address.");
        }

        // The origin, not the whole address. postMessage compares the target against the receiver's origin,
        // and a value carrying a path never matches - the message is silently dropped, which reads as a
        // provider that stopped answering.
        var opOrigin = checkSessionIframe.GetLeftPart(UriPartial.Authority);

        var nonce = NewNonce();

        var html = Template
            .Replace("{{checkSessionIframe}}", HttpUtility.HtmlAttributeEncode(check.CheckSessionIframe))
            .Replace("{{nonce}}", nonce)
            .Replace("{{opOrigin}}", JavaScriptString(opOrigin))
            .Replace("{{selfOrigin}}", JavaScriptString(selfOrigin.GetLeftPart(UriPartial.Authority)))
            .Replace("{{message}}", JavaScriptString(check.Message))
            .Replace(
                "{{intervalMs}}",
                ((long)options.Value.PollingInterval.TotalMilliseconds).ToString(
                    System.Globalization.CultureInfo.InvariantCulture));

        return new SessionCheckFrame(html, ContentSecurityPolicy(nonce, opOrigin));
    }

    /// <summary>
    /// The policy this page is served under.
    /// </summary>
    /// <remarks>
    /// Written as an allow-list of exactly what the page does: it frames the provider's address and runs one
    /// inline script, and needs nothing else. The nonce is what lets that one script run while any script an
    /// injection managed to add does not, which is the whole reason the policy is worth having on a page
    /// whose only job is to relay a word between two frames.
    /// </remarks>
    private static string ContentSecurityPolicy(string nonce, string opOrigin)
        => $"default-src 'none'; frame-src {opOrigin}; script-src 'nonce-{nonce}'";

    /// <summary>
    /// A fresh nonce for each rendering, since a reused one is not a nonce.
    /// </summary>
    private static string NewNonce() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

    /// <summary>
    /// Escapes a value being placed inside a JavaScript string literal.
    /// </summary>
    /// <remarks>
    /// Every value substituted into the script comes from the provider's metadata or this client's own
    /// configuration rather than from a request, so none of it is attacker-supplied in the ordinary sense.
    /// It is escaped anyway: the day one of them becomes host-configurable from something a user typed, the
    /// escaping is already there, and nobody has to notice that it was not.
    /// </remarks>
    private static string JavaScriptString(string value)
        => value
            .Replace("\\", "\\\\")
            .Replace("\"", "\\\"")
            .Replace("<", "\\u003c")
            .Replace(">", "\\u003e")
            .Replace("\r", "\\r")
            .Replace("\n", "\\n");

    private static string ReadTemplate()
    {
        using var stream = typeof(SessionCheckFrameBuilder).GetTypeInfo().Assembly
            .GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException(
                $"The embedded resource '{ResourceName}' is missing from the assembly.");

        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
