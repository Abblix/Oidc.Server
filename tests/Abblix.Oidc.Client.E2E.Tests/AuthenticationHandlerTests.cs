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
using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.E2E.Tests;

/// <summary>
/// Signing in through the ASP.NET handler: a browser asks for a protected page and ends up reading it.
/// </summary>
/// <remarks>
/// The other suite drives the client's services directly and proves the protocol works. This one proves the
/// wiring does: that a challenge redirects to the provider, that the callback turns into a session cookie,
/// and that an authorization check then lets the user through. Nothing here reaches into the client - a
/// browser talking to an application is all it is.
/// </remarks>
public class AuthenticationHandlerTests(ClientHostFixture fixture) : IClassFixture<ClientHostFixture>
{
    private const string Subject = "e2e-subject";

    /// <summary>
    /// An unauthenticated visitor to a protected page is sent to the provider to sign in.
    /// </summary>
    [Fact]
    public async Task AProtectedPageChallengesTheVisitor()
    {
        using var browser = fixture.CreateBrowser();

        using var response = await browser.GetAsync(
            ClientHostFixture.ProtectedPath, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.StartsWith(
            ClientAgainstServerFixture.Issuer,
            response.Headers.Location!.OriginalString,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The whole round trip: challenge, the provider's answer, the callback, and the protected page read by
    /// a user the application now knows.
    /// </summary>
    /// <remarks>
    /// This is the case every earlier test was building towards, and the only one that says the pieces are
    /// wired together rather than merely correct apart.
    /// </remarks>
    [Fact]
    public async Task ASignedInUserReadsTheProtectedPage()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        using var browser = fixture.CreateBrowser();

        // The application sends the visitor to the provider.
        using var challenge = await browser.GetAsync(ClientHostFixture.ProtectedPath, cancellationToken);
        var authorizationRequest = challenge.Headers.Location!;

        // The provider authenticates and redirects back to this application's callback.
        using var providerBrowser = fixture.Provider.CreateBrowser();
        using var authorized = await providerBrowser.GetAsync(authorizationRequest, cancellationToken);
        var callback = authorized.Headers.Location!;

        Assert.Equal(HttpStatusCode.Found, challenge.StatusCode);
        Assert.StartsWith("https://client.example.com/cb", callback.OriginalString, StringComparison.Ordinal);

        // The callback lands on the application, which signs the user in and sends them where they were
        // heading.
        using var signedIn = await browser.GetAsync(callback, cancellationToken);

        Assert.Equal(HttpStatusCode.Found, signedIn.StatusCode);
        Assert.Equal(ClientHostFixture.ProtectedPath, signedIn.Headers.Location!.OriginalString);

        // And now the page opens, for the user the provider authenticated.
        using var page = await browser.GetAsync(ClientHostFixture.ProtectedPath, cancellationToken);

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Equal(Subject, await page.Content.ReadAsStringAsync(cancellationToken));
    }

    /// <summary>
    /// A callback that matches no login this application started is refused rather than signed in.
    /// </summary>
    /// <remarks>
    /// The state a callback carries is the only thing tying it to a login, and one that ties it to nothing
    /// is either a stale attempt or somebody else's. Either way there is no login to finish.
    /// </remarks>
    [Fact]
    public async Task AnUnknownCallbackDoesNotSignAnybodyIn()
    {
        using var browser = fixture.CreateBrowser();

        using var response = await browser.GetAsync(
            $"{ClientHostFixture.CallbackPath}?code=made-up&state=never-issued",
            TestContext.Current.CancellationToken);

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);

        // And the protected page is still shut.
        using var page = await browser.GetAsync(
            ClientHostFixture.ProtectedPath, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, page.StatusCode);
    }

    /// <summary>
    /// A Logout Token the provider posts to the back-channel endpoint reaches the application, which is told
    /// whose sessions to end.
    /// </summary>
    [Fact]
    public async Task ARefusedLogoutTokenIsAnsweredBadRequest()
    {
        using var browser = fixture.CreateBrowser();

        // Counted rather than required to be empty: the fixture is shared with the test that logs out for
        // real, and nothing fixes the order they run in.
        var loggedOutBefore = fixture.LoggedOutSubjects.Count;

        using var content = new FormUrlEncodedContent(
            [new KeyValuePair<string, string>("logout_token", "not.a.token")]);

        using var response = await browser.PostAsync(
            ClientHostFixture.BackChannelLogoutPath, content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(
            new CacheControlHeaderValue { NoStore = true }, response.Headers.CacheControl);
        Assert.Equal(loggedOutBefore, fixture.LoggedOutSubjects.Count);
    }

    /// <summary>
    /// Signs a browser in through the application, the way the round-trip test does, and returns it holding
    /// the session cookie.
    /// </summary>
    private async Task<HttpClient> SignInAsync(CancellationToken cancellationToken)
    {
        var browser = fixture.CreateBrowser();

        using var challenge = await browser.GetAsync(ClientHostFixture.ProtectedPath, cancellationToken);

        using var providerBrowser = fixture.Provider.CreateBrowser();
        using var authorized = await providerBrowser.GetAsync(
            challenge.Headers.Location!, cancellationToken);

        using var signedIn = await browser.GetAsync(authorized.Headers.Location!, cancellationToken);

        return browser;
    }

    /// <summary>
    /// The provider ends the session and tells this application to do the same, over the back channel.
    /// </summary>
    /// <remarks>
    /// The case the unit tests cannot reach. There the Logout Token is one this repository signed for
    /// itself; here it is minted by the provider, posted by the provider over its own transport, and read
    /// by an application that was only ever told the provider's address. Every step between the two is a
    /// place the two halves could have disagreed.
    /// </remarks>
    [Fact]
    public async Task TheProviderLogsTheApplicationOutOverTheBackChannel()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        using var browser = await SignInAsync(cancellationToken);

        var identityToken = await browser.GetStringAsync(
            ClientHostFixture.IdentityTokenPath, cancellationToken);

        Assert.False(string.IsNullOrEmpty(identityToken));

        var loggedOutBefore = fixture.LoggedOutSubjects.Count;

        // The user signs out at the provider, which is what sets the notification going.
        // Built as the client the hint was issued to. Section 2 makes the provider verify that the
        // client_id beside a hint is the one the ID Token was issued for, so any other client's logout
        // request is refused - which is how this test first failed.
        await using var logoutClient = fixture.Provider.CreateOidcClient(
            clientId: ClientHostFixture.ClientId);

        var logoutUri = await logoutClient
            .GetRequiredService<IOidcClient>()
            .CreateEndSessionRequestAsync(identityToken, cancellationToken: cancellationToken);

        using var providerBrowser = fixture.Provider.CreateBrowser();
        using var loggedOut = await providerBrowser.GetAsync(logoutUri, cancellationToken);

        Assert.NotEqual(HttpStatusCode.BadRequest, loggedOut.StatusCode);
        Assert.Equal(loggedOutBefore + 1, fixture.LoggedOutSubjects.Count);
        Assert.Equal(Subject, fixture.LoggedOutSubjects[^1]);
    }
}
