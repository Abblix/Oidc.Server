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

using System.Net;
using System.Text.RegularExpressions;
using Jint;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.E2E.Tests;

/// <summary>
/// The session-watching frame, as this application serves it and as a browser would run it.
/// </summary>
/// <remarks>
/// The page ships a script, and a string comparison against a script is not a test of what it does. So the
/// document is fetched from the running application, for a session a real provider issued, and then its
/// script is executed - the messages it sends and the ones it refuses are observed rather than read.
/// What the interpreter cannot supply is a browser's enforcement: it will not stop a page from lying about
/// an origin. That is the point of driving it this way. The origin check is the one line in the script that
/// decides who may end a session, so it is exercised by handing the script a message from the wrong origin
/// and requiring silence.
/// </remarks>
/// <remarks>
/// What is still not covered here, and what would cover it. Three things are outside an interpreter's
/// reach: that the browser, not the sender, decides what <c>event.origin</c> says; that it enforces the
/// target origin a message was addressed to; and that the Content-Security-Policy actually stops a script
/// the page did not author. A fourth is bigger - the agreement between this frame and the provider's own,
/// which in this solution is ours too. That frame uses <c>crypto.subtle</c> and <c>document.cookie</c> to
/// recompute the session state, so the full circle - sign in, ask, hear "unchanged", end the session
/// elsewhere, hear "changed" - is proved nowhere.
/// The way to prove it is Playwright for .NET: one package, the browser out of process, and C# driving it.
/// It was weighed and deferred rather than overlooked, and what it costs is worth writing down so the next
/// person does not rediscover it. Both hosts would move from the in-process test server, which opens no
/// socket a browser can reach, to real Kestrel on ports - no hardship, and two ports are two origins, which
/// is exactly what postMessage wants. The provider requires HTTPS, so a development certificate and a
/// browser told to accept it. And the runner image would need a browser: our job pods are rootless, so
/// "playwright install --with-deps" cannot run there, which makes this a change to the runner image in
/// another repository rather than a package reference here.
/// </remarks>
public class SessionCheckFrameTests(ClientHostFixture fixture) : IClassFixture<ClientHostFixture>
{
    /// <summary>
    /// A ceiling on every regex match below, so a pattern can never run away on unexpected input. The input
    /// here is the frame this suite fetched, not an attacker's, but a bounded match costs nothing and is the
    /// habit that keeps a later copy of one of these patterns from being the one that hangs.
    /// </summary>
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// The recorder the interpreter collects into when the frame's script posts a message to the page
    /// hosting it. Named because what each case asserts is whether something arrived here at all.
    /// </summary>
    private const string ToParent = "toParent";

    /// <summary>
    /// Signs in and fetches the frame the way the hosting page would.
    /// </summary>
    private async Task<(HttpResponseMessage Response, string Html)> FetchFrameAsync(
        CancellationToken cancellationToken)
    {
        using var browser = await fixture.SignInAsync(cancellationToken);

        var response = await browser.GetAsync(ClientHostFixture.SessionCheckPath, cancellationToken);

        return (response, await response.Content.ReadAsStringAsync(cancellationToken));
    }

    /// <summary>
    /// The frame names the provider's own address, taken from what the provider published rather than from
    /// anything written into this application.
    /// </summary>
    [Fact]
    public async Task TheFrameEmbedsTheProviderFrame()
    {
        var (response, html) = await FetchFrameAsync(TestContext.Current.CancellationToken);
        response.Dispose();

        var metadata = await fixture.Provider.CreateOidcClient()
            .GetRequiredService<Features.Discovery.IProviderMetadataProvider>()
            .GetMetadataAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(metadata.CheckSessionIframe);
        Assert.Contains($"src=\"{metadata.CheckSessionIframe}\"", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The page is served under a policy that allows exactly what it does and nothing else, and the nonce in
    /// the policy is the one its own script carries.
    /// </summary>
    /// <remarks>
    /// The pair is what makes the policy worth having: the script runs because the policy names its nonce,
    /// and a script an injection added does not, because it cannot know one.
    /// </remarks>
    [Fact]
    public async Task ThePolicyNamesTheScriptsOwnNonce()
    {
        var (response, html) = await FetchFrameAsync(TestContext.Current.CancellationToken);

        var policy = Assert.Single(response.Headers.GetValues("Content-Security-Policy"));
        response.Dispose();

        Assert.Contains("default-src 'none'", policy, StringComparison.Ordinal);
        Assert.Contains($"frame-src {ClientAgainstServerFixture.Issuer}", policy, StringComparison.Ordinal);

        var nonce = Regex.Match(policy, @"'nonce-([^']+)'", RegexOptions.None, RegexTimeout).Groups[1].Value;
        Assert.NotEmpty(nonce);
        Assert.Contains($"nonce=\"{nonce}\"", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every rendering gets its own nonce, since a reused one is not a nonce.
    /// </summary>
    [Fact]
    public async Task EachRenderingGetsItsOwnNonce()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var (first, firstHtml) = await FetchFrameAsync(cancellationToken);
        var (second, secondHtml) = await FetchFrameAsync(cancellationToken);

        first.Dispose();
        second.Dispose();

        Assert.NotEqual(NonceOf(firstHtml), NonceOf(secondHtml));
    }

    /// <summary>
    /// The document belongs to one session, so it is not cacheable.
    /// </summary>
    [Fact]
    public async Task TheFrameIsNotCacheable()
    {
        var (response, _) = await FetchFrameAsync(TestContext.Current.CancellationToken);

        Assert.True(response.Headers.CacheControl?.NoStore);
        response.Dispose();
    }

    /// <summary>
    /// A visitor who is not signed in has no session to watch, and gets an empty document rather than a
    /// login screen - a frame is no place for one.
    /// </summary>
    [Fact]
    public async Task WithoutASessionThereIsNothingToWatch()
    {
        using var browser = fixture.CreateBrowser();

        using var response = await browser.GetAsync(
            ClientHostFixture.SessionCheckPath, TestContext.Current.CancellationToken);

        // The authorization check answers first, which is itself the right answer: nothing about a session
        // is served to someone who has none.
        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    private static string NonceOf(string html)
        => Regex.Match(html, @"nonce=""([^""]+)""", RegexOptions.None, RegexTimeout).Groups[1].Value;

    /// <summary>
    /// A browser-sized stub: enough of a window and a document for the frame's script to run, recording
    /// every message it sends so the test can look at them.
    /// </summary>
    /// <remarks>
    /// Deliberately permissive. A real browser would refuse to deliver a message claiming an origin it did
    /// not come from; this one delivers whatever the test says, which is what makes it useful - the script's
    /// own origin check is then the only thing standing between a forged message and a logged-out user, and
    /// that is exactly the line under test.
    /// </remarks>
    private const string BrowserStub = """
        var recorded = { toOp: [], toParent: [] };
        var listeners = { message: [], load: [] };

        var window = {
            addEventListener: function (type, fn) { listeners[type].push(fn); },
            parent: {
                postMessage: function (data, origin) {
                    recorded.toParent.push({ data: data, origin: origin });
                }
            }
        };

        var document = {
            getElementById: function () {
                return {
                    contentWindow: {
                        postMessage: function (data, origin) {
                            recorded.toOp.push({ data: data, origin: origin });
                        }
                    },
                    addEventListener: function (type, fn) { listeners[type].push(fn); }
                };
            }
        };

        function setInterval() { return 0; }

        function deliver(origin, data) {
            listeners.message.forEach(function (fn) { fn({ origin: origin, data: data }); });
        }

        function load() {
            listeners.load.forEach(function (fn) { fn(); });
        }
        """;

    /// <summary>
    /// Loads the frame's own script into a JavaScript engine, ready to be driven.
    /// </summary>
    private async Task<Engine> RunScriptAsync(CancellationToken cancellationToken)
    {
        var (response, html) = await FetchFrameAsync(cancellationToken);
        response.Dispose();

        var script = Regex.Match(html, @"<script[^>]*>(.*?)</script>", RegexOptions.Singleline, RegexTimeout)
            .Groups[1].Value;

        Assert.NotEmpty(script);

        var engine = new Engine();
        Drive(engine, BrowserStub);
        Drive(engine, script);

        return engine;
    }

    /// <summary>
    /// Runs a line of script against the engine.
    /// </summary>
    /// <remarks>
    /// Its own method so the interpreter call does not sit inside an async one, where an analyzer mistakes
    /// it for a database command and asks for an ExecuteAsync that Jint does not have.
    /// </remarks>
    private static void Drive(Engine engine, string script) => engine.Execute(script);

    private static string Recorded(Engine engine, string which)
        => engine.Evaluate($"JSON.stringify(recorded.{which})").AsString();

    /// <summary>
    /// Once its frame has loaded, the script asks the provider - with the message section 3.1 defines, sent
    /// to the provider's origin rather than to anyone who will listen.
    /// </summary>
    [Fact]
    public async Task ItAsksTheProviderWithATargetedMessage()
    {
        var engine = await RunScriptAsync(TestContext.Current.CancellationToken);

        Drive(engine, "load();");

        var sent = Recorded(engine, "toOp");
        Assert.Contains(ClientHostFixture.ClientId, sent, StringComparison.Ordinal);
        Assert.Contains(ClientAgainstServerFixture.Issuer, sent, StringComparison.Ordinal);
        Assert.DoesNotContain("\"origin\":\"*\"", sent, StringComparison.Ordinal);
    }

    /// <summary>
    /// Told the session changed, the script asks the page to re-check. Section 3.2: "Upon receipt of
    /// changed, the RP MUST perform re-authentication with prompt=none."
    /// </summary>
    [Fact]
    public async Task ItAsksForARecheckWhenTheSessionChanged()
    {
        var engine = await RunScriptAsync(TestContext.Current.CancellationToken);

        Drive(engine, $"deliver('{ClientAgainstServerFixture.Issuer}', 'changed');");

        Assert.Contains("abblix-oidc-session:recheck", Recorded(engine, ToParent), StringComparison.Ordinal);
    }

    /// <summary>
    /// The same word from anywhere else is ignored. Section 6: "The RP iframe MUST enforce that it only
    /// processes messages from the origin of the OP frame. It MUST reject postMessage requests from any
    /// other source origin to prevent cross-site scripting attacks."
    /// </summary>
    /// <remarks>
    /// The one that matters. Without this line any page that framed this one could end the user's session
    /// by saying the word.
    /// </remarks>
    [Fact]
    public async Task ItIgnoresAMessageFromAnotherOrigin()
    {
        var engine = await RunScriptAsync(TestContext.Current.CancellationToken);

        Drive(engine, "deliver('https://evil.example.com', 'changed');");

        Assert.Equal("[]", Recorded(engine, ToParent));
    }

    /// <summary>
    /// An error is passed on as an error and never as a reason to re-check. Section 3.2: upon receiving
    /// error the RP "MUST NOT perform re-authentication with prompt=none".
    /// </summary>
    /// <remarks>
    /// Why the frame reports a decision rather than the provider's word: a page handed "error" and left to
    /// tell it from "changed" is a page that can get this wrong, and this is the one it must not.
    /// </remarks>
    [Fact]
    public async Task AnErrorIsNeverARecheck()
    {
        var engine = await RunScriptAsync(TestContext.Current.CancellationToken);

        Drive(engine, $"deliver('{ClientAgainstServerFixture.Issuer}', 'error');");

        var told = Recorded(engine, ToParent);
        Assert.Contains("abblix-oidc-session:error", told, StringComparison.Ordinal);
        Assert.DoesNotContain("recheck", told, StringComparison.Ordinal);
    }

    /// <summary>
    /// An unchanged session is reported as such, and is not a reason to do anything.
    /// </summary>
    [Fact]
    public async Task AnUnchangedSessionIsReportedPlainly()
    {
        var engine = await RunScriptAsync(TestContext.Current.CancellationToken);

        Drive(engine, $"deliver('{ClientAgainstServerFixture.Issuer}', 'unchanged');");

        var told = Recorded(engine, ToParent);
        Assert.Contains("abblix-oidc-session:ok", told, StringComparison.Ordinal);
        Assert.DoesNotContain("recheck", told, StringComparison.Ordinal);
    }

    /// <summary>
    /// A word the provider frame never says is not acted on either, however it arrives.
    /// </summary>
    [Fact]
    public async Task AnUnknownAnswerIsIgnored()
    {
        var engine = await RunScriptAsync(TestContext.Current.CancellationToken);

        Drive(engine, $"deliver('{ClientAgainstServerFixture.Issuer}', 'logged-out');");

        Assert.Equal("[]", Recorded(engine, ToParent));
    }
}
