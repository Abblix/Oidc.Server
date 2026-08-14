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

using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The authorization endpoint's other answer: instead of a response to the client, a redirect that sends the
/// user's browser to an interaction the request cannot proceed without - signing in, choosing an account,
/// creating one, or granting consent (OpenID Connect Core 1.0 section 3.1.2.1, and Initiating User
/// Registration via OpenID Connect 1.0 for <c>prompt=create</c>).
/// </summary>
/// <remarks>
/// None of these arms had been driven through either adapter. They are worth driving for what they do rather
/// than for the count: this is the branch that sends an end user to the login page, and it can fail in two
/// ways that no other test would notice. It can pick the wrong destination, which sends the user somewhere
/// that cannot serve them. And it can lose the request, which leaves the interaction page with nothing to
/// return to - the user signs in and their authorization request is gone.
///
/// So each case asserts both: which destination was chosen, and that the request reached it. The request
/// does not travel as query parameters: the endpoint stores it and passes a single <c>request_uri</c>
/// handle, which the interaction page resolves. Asserting the handle is therefore asserting the thing the
/// page actually depends on.
///
/// The destinations are distinct paths in the test host on purpose. A host that configures only
/// <c>LoginUri</c> - as this one did - cannot reach the other arms at all: they answer with a loud
/// "not configured" failure rather than a redirect, so the branch stays dark and the omission looks like
/// coverage rather than like a gap.
/// </remarks>
public class InteractionRedirectTests(TestFactory factory) : TestBase(factory)
{
    private const string LoginPath = "/login";
    private const string ConsentPath = "/consent";
    private const string AccountSelectionPath = "/select-account";
    private const string RegistrationPath = "/register";

    // PKCE included because the client requires it: without it the request is refused by validation and the
    // endpoint answers the client's redirect_uri with an error, never reaching the interaction branch at all.
    private static Dictionary<string, string> AuthorizeParameters(string prompt, string state, string challenge)
        => new()
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = state,
            [AuthorizationRequest.Parameters.Prompt] = prompt,
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        };

    /// <summary>
    /// The interaction page is handed one parameter: a reference to the stored authorization request. Without
    /// it the page cannot tell what was asked for and has nowhere to send the user afterwards.
    /// </summary>
    private static void AssertCarriesTheStoredRequest(Uri location)
    {
        var handle = QueryOf(location)[AuthorizationRequest.Parameters.RequestUri];

        Assert.False(
            string.IsNullOrEmpty(handle),
            $"the interaction redirect carried no {AuthorizationRequest.Parameters.RequestUri}: {location}");
    }

    /// <summary>The query the endpoint appended, whether the location it answered with is relative or absolute.
    /// </summary>
    private static System.Collections.Specialized.NameValueCollection QueryOf(Uri location)
        => System.Web.HttpUtility.ParseQueryString(
            location.IsAbsoluteUri ? location.Query : location.OriginalString.Split('?').ElementAtOrDefault(1) ?? "");

    /// <summary>The path the browser was sent to, whether the endpoint answered with a relative or an
    /// absolute location.</summary>
    private static string PathOf(Uri location)
        => location.IsAbsoluteUri
            ? location.AbsolutePath
            : location.OriginalString.Split('?')[0];

    /// <summary>
    /// Drives /authorize and returns where the endpoint sent the browser, asserting it redirected at all.
    /// </summary>
    private static async Task<Uri> InteractionRedirectAsync(
        HttpClient client, DiscoveryDocument discovery, string prompt, string state)
    {
        var (_, challenge) = GeneratePkcePair();
        var uri = QueryHelpers.BuildUri(
            discovery.AuthorizationEndpoint, AuthorizeParameters(prompt, state, challenge));

        var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"/authorize answered {(int)response.StatusCode} for prompt={prompt}, expected a redirect to the " +
            "interaction page. Body: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        return response.Headers.Location
            ?? throw new InvalidOperationException("/authorize redirected without a Location header");
    }

    [Fact]
    public async Task Prompt_login_sends_the_user_to_the_login_page_with_the_request()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var state = Guid.NewGuid().ToString("N");

        var location = await InteractionRedirectAsync(client, discovery, Prompts.Login, state);

        Assert.Equal(LoginPath, PathOf(location));
        AssertCarriesTheStoredRequest(location);
    }

    [Fact]
    public async Task Prompt_select_account_sends_the_user_to_the_account_chooser()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var state = Guid.NewGuid().ToString("N");

        var location = await InteractionRedirectAsync(client, discovery, Prompts.SelectAccount, state);

        Assert.Equal(AccountSelectionPath, PathOf(location));
        AssertCarriesTheStoredRequest(location);
    }

    /// <summary>
    /// <c>prompt=create</c> takes the user to account creation whether or not they already have a session,
    /// and the prompt travels with the request so a combined login and registration page can branch on it.
    /// </summary>
    [Fact]
    public async Task Prompt_create_sends_the_user_to_registration_carrying_the_prompt()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var state = Guid.NewGuid().ToString("N");

        var location = await InteractionRedirectAsync(client, discovery, Prompts.Create, state);

        Assert.Equal(RegistrationPath, PathOf(location));
        AssertCarriesTheStoredRequest(location);
    }

    /// <summary>
    /// The consent destination is reached when the consent provider reports something still pending, which no
    /// prompt value can force on its own. The default host grants everything, so this one substitutes a
    /// provider that withholds consent for the requested scope, which is the state a real deployment is in
    /// the first time a user meets a client.
    /// </summary>
    [Fact]
    public async Task A_pending_consent_sends_the_user_to_the_consent_page()
    {
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Replace(ServiceDescriptor.Scoped<IUserConsentsProvider, WithholdingConsentsProvider>())));

        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);

        var location = await InteractionRedirectAsync(
            client, discovery, Prompts.Consent, Guid.NewGuid().ToString("N"));

        Assert.Equal(ConsentPath, PathOf(location));
        AssertCarriesTheStoredRequest(location);
    }

    /// <summary>
    /// Reports the requested scope as still needing consent, and nothing as granted, so the endpoint has to
    /// send the user to collect it.
    /// </summary>
    private sealed class WithholdingConsentsProvider : IUserConsentsProvider
    {
        public Task<UserConsents> GetUserConsentsAsync(
            ValidAuthorizationRequest request, AuthSession authSession)
            => Task.FromResult(new UserConsents
            {
                Granted = new ConsentDefinition([], []),
                Pending = new ConsentDefinition(
                    (request.Model.Scope ?? []).Select(scope => new ScopeDefinition(scope)).ToArray(),
                    []),
            });
    }
}
