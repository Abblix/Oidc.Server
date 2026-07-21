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
using Abblix.Oidc.Client.Features.ProtectedResources;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.E2E.Tests;

/// <summary>
/// Calling a protected API with the token the signed-in user was issued.
/// </summary>
/// <remarks>
/// Three real parties: a provider that issued the token, an application that kept it with the session, and
/// an API that hands it back to the provider to find out whom it belongs to. Nothing here asserts a status
/// code where it could assert a consequence - the API answers with the subject it learned, and that subject
/// has to be the one who signed in.
/// </remarks>
public class ProtectedResourceTests(ClientHostFixture fixture) : IClassFixture<ClientHostFixture>
{
    private const string Subject = "e2e-subject";

    /// <summary>
    /// Signs a browser in and returns it holding the session cookie.
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
    /// The whole point: the application calls its API on the user's behalf, and the API recognises that
    /// user from the token the client attached.
    /// </summary>
    /// <remarks>
    /// The assertion is the subject, not a 200. A status code would survive the client attaching nothing at
    /// all if the API were lenient, and it would survive the client attaching somebody else's token.
    /// </remarks>
    [Fact]
    public async Task TheApiRecognisesTheSignedInUser()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        using var browser = await SignInAsync(cancellationToken);

        using var response = await browser.GetAsync(
            ClientHostFixture.CallApiPath, cancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Subject, await response.Content.ReadAsStringAsync(cancellationToken));
    }

    /// <summary>
    /// A caller with no session has no token to present, and is refused by name before anything is sent.
    /// </summary>
    /// <remarks>
    /// The reason matters more than the refusal: "there is no session" and "the token expired" and "tokens
    /// are not being stored" have three different fixes in three different files, and a single message would
    /// make them one grep that distinguishes nothing.
    /// </remarks>
    [Fact]
    public async Task WithoutASessionThereIsNoTokenToPresent()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        await using var scope = fixture.Services.CreateAsyncScope();

        var client = scope.ServiceProvider.GetRequiredService<IHttpClientFactory>()
            .CreateClient(ClientHostFixture.ApiClientName);

        var exception = await Assert.ThrowsAsync<AccessTokenUnavailableException>(
            () => client.GetAsync("42", cancellationToken));

        Assert.Equal(AccessTokenUnavailableReason.NoAmbientSession, exception.Reason);
    }
}
