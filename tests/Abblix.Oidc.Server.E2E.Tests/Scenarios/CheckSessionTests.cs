// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Mime;
using System.Text.RegularExpressions;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Microsoft.Net.Http.Headers;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of the check session iframe (OpenID Connect Session Management) served by the MVC adapter.
/// </summary>
/// <remarks>
/// This page is the only part of the server that a relying party is expected to embed in a frame of its own
/// origin, and it is the only server-rendered HTML that must therefore be exempt from the anti-framing headers
/// applied everywhere else. Session monitoring fails silently when any of that is wrong: the browser drops the
/// frame, or blocks the inline script, and the relying party simply never learns that the user signed out.
/// Nothing in the suite walked this endpoint before, so every part of it - the formatter, the caching decorator
/// and the cache - shipped unexercised.
/// </remarks>
public class CheckSessionTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// The CSP directive that controls who may frame a document. There is no library constant for the directive
    /// name on its own: <c>AntiFramingHeaders.ContentSecurityPolicy</c> holds the complete deny-everything value,
    /// and this test needs to reject any framing restriction, not only that exact one.
    /// </summary>
    private const string FrameAncestorsDirective = "frame-ancestors";

    /// <summary>
    /// A ceiling on how long either pattern may run. Both are linear and match a header or a short document,
    /// so a second is unreachable in practice; it is there because a pattern applied to input from outside the
    /// test has no business running unbounded, and because the analyzer is right that this is where such a
    /// habit starts.
    /// </summary>
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(1);

    private static readonly Regex CspNoncePattern =
        new("'nonce-(?<value>[^']+)'", RegexOptions.Compiled, MatchTimeout);

    private static readonly Regex ScriptNoncePattern =
        new("<script nonce=\"(?<value>[^\"]+)\"", RegexOptions.Compiled, MatchTimeout);

    [Fact]
    public async Task The_check_session_iframe_is_published_in_discovery()
    {
        // A relying party learns the iframe URL only from discovery. An endpoint that is enabled but unadvertised
        // leaves every client with session monitoring turned off and no way to notice.
        var discovery = await FetchDiscoveryAsync(CreateClient());

        Assert.NotNull(discovery.CheckSessionIframe);
    }

    [Fact]
    public async Task The_check_session_iframe_is_served_as_html()
    {
        // The browser decides how to treat the frame from the content type, not from the bytes. Served as
        // anything but HTML, the document never renders, the script inside it never runs, and the relying
        // party's postMessage handshake gets no answer at all.
        var (response, _) = await FetchCheckSessionPageAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(MediaTypeNames.Text.Html, response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task The_check_session_iframe_is_not_forbidden_from_being_framed()
    {
        // Every other HTML page this server emits carries the anti-framing pair, because being framed by a
        // stranger is an attack on those pages. This one is the exact opposite: it exists to be framed by the
        // relying party. A frame-ancestors restriction or an X-Frame-Options header here would break session
        // monitoring for every client at once, while a test of the page's content still passed happily.
        var (response, _) = await FetchCheckSessionPageAsync();

        var policy = GetContentSecurityPolicy(response);
        Assert.DoesNotContain(FrameAncestorsDirective, policy, StringComparison.OrdinalIgnoreCase);
        Assert.False(response.Headers.Contains(HeaderNames.XFrameOptions));
    }

    [Fact]
    public async Task The_policy_nonce_matches_the_nonce_on_the_inline_script()
    {
        // The page's only script is inline, and the policy admits scripts by nonce alone. If the value in the
        // header and the value in the markup ever drift apart, the browser refuses to run the script and the
        // page becomes an empty frame that answers nothing - with a 200 status and correct-looking HTML.
        var (response, body) = await FetchCheckSessionPageAsync();

        var policyNonce = ExtractNonce(CspNoncePattern, GetContentSecurityPolicy(response), "Content-Security-Policy");
        var scriptNonce = ExtractNonce(ScriptNoncePattern, body, "inline script tag");

        Assert.Equal(policyNonce, scriptNonce);
    }

    [Fact]
    public async Task Each_request_gets_a_fresh_nonce_despite_the_response_being_cached()
    {
        // The formatted result is cached in a process-wide cache keyed by the cookie name, so every request
        // after the first is served from one shared object. The nonce still has to be minted per request: a
        // nonce that survives in the cache is a constant value an attacker can read once and then reuse to get
        // injected script past the policy, which is the whole thing the nonce was there to prevent.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var first = await ReadNoncePairAsync(client, discovery);
        var second = await ReadNoncePairAsync(client, discovery);

        Assert.NotEqual(first.PolicyNonce, second.PolicyNonce);

        // Each response must stay internally consistent, otherwise the second visitor gets a page whose script
        // the browser will not run.
        Assert.Equal(first.PolicyNonce, first.ScriptNonce);
        Assert.Equal(second.PolicyNonce, second.ScriptNonce);
    }

    private async Task<(HttpResponseMessage Response, string Body)> FetchCheckSessionPageAsync()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        return await GetPageAsync(client, discovery);
    }

    private static async Task<(HttpResponseMessage Response, string Body)> GetPageAsync(
        HttpClient client, DiscoveryDocument discovery)
    {
        Assert.NotNull(discovery.CheckSessionIframe);
        var response = await client.GetAsync(discovery.CheckSessionIframe, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return (response, body);
    }

    private static async Task<(string PolicyNonce, string ScriptNonce)> ReadNoncePairAsync(
        HttpClient client, DiscoveryDocument discovery)
    {
        var (response, body) = await GetPageAsync(client, discovery);
        return (
            ExtractNonce(CspNoncePattern, GetContentSecurityPolicy(response), "Content-Security-Policy"),
            ExtractNonce(ScriptNoncePattern, body, "inline script tag"));
    }

    private static string GetContentSecurityPolicy(HttpResponseMessage response)
    {
        Assert.True(
            response.Headers.TryGetValues(HeaderNames.ContentSecurityPolicy, out var values),
            "The check session page was served without a Content-Security-Policy header.");
        return Assert.Single(values!);
    }

    private static string ExtractNonce(Regex pattern, string source, string sourceName)
    {
        var match = pattern.Match(source);
        Assert.True(match.Success, $"No nonce found in the {sourceName}: {source}");
        return match.Groups["value"].Value;
    }
}
