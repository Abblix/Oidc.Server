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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// The Minimal API counterpart of the MVC suite's interaction-redirect scenarios, driving the same four
/// destinations through this adapter: sign-in, account selection, registration and consent (OpenID Connect
/// Core 1.0 section 3.1.2.1, and Initiating User Registration via OpenID Connect 1.0 for
/// <c>prompt=create</c>).
/// </summary>
/// <remarks>
/// Deliberately the same cases as the MVC suite rather than a different selection. The two adapters are meant
/// to be interchangeable, and a response one renders correctly while the other does not is the defect that a
/// difference in test coverage hides rather than reveals. Running the pair is what checks the property
/// neither can check alone.
///
/// The request does not travel as query parameters: the endpoint stores it and passes a single
/// <c>request_uri</c> handle for the interaction page to resolve, so that handle is what each case asserts.
/// </remarks>
public sealed class InteractionRedirectTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private const string LoginPath = "/login";
    private const string ConsentPath = "/consent";
    private const string AccountSelectionPath = "/select-account";
    private const string RegistrationPath = "/register";

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestFactory.BaseAddress,
        });

    // PKCE included because the client requires it: without it the request is refused by validation and the
    // endpoint answers the client's redirect_uri with an error, never reaching the interaction branch at all.
    private static Dictionary<string, string> AuthorizeParameters(string prompt, string challenge) => new()
    {
        [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
        [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
        [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
        [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
        [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
        [AuthorizationRequest.Parameters.Prompt] = prompt,
        [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
        [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
    };

    private static async Task<Uri> InteractionRedirectAsync(HttpClient client, string prompt)
    {
        var discovery = await client.FetchDiscoveryAsync();
        var endpoint = OidcFlows.Endpoint(
            discovery, ConfigurationResponse.Parameters.AuthorizationEndpoint);
        var (_, challenge) = OidcFlows.Pkce();

        var uri = OidcFlows.BuildQuery(endpoint, AuthorizeParameters(prompt, challenge));
        var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"/authorize answered {(int)response.StatusCode} for prompt={prompt}, expected a redirect to the " +
            "interaction page. Body: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        return response.Headers.Location
            ?? throw new InvalidOperationException("/authorize redirected without a Location header");
    }

    /// <summary>The path the browser was sent to, whether the location is relative or absolute.</summary>
    private static string PathOf(Uri location)
        => location.IsAbsoluteUri ? location.AbsolutePath : location.OriginalString.Split('?')[0];

    /// <summary>
    /// The interaction page is handed one parameter: a reference to the stored authorization request. Without
    /// it the page cannot tell what was asked for and has nowhere to send the user afterwards.
    /// </summary>
    private static void AssertCarriesTheStoredRequest(Uri location)
    {
        var query = location.IsAbsoluteUri
            ? location.Query
            : location.OriginalString.Split('?').ElementAtOrDefault(1) ?? string.Empty;

        var handle = System.Web.HttpUtility.ParseQueryString(query)[AuthorizationRequest.Parameters.RequestUri];

        Assert.False(
            string.IsNullOrEmpty(handle),
            $"the interaction redirect carried no {AuthorizationRequest.Parameters.RequestUri}: {location}");
    }

    [Fact]
    public async Task Prompt_login_sends_the_user_to_the_login_page()
    {
        var location = await InteractionRedirectAsync(CreateClientFor(factory), Prompts.Login);

        Assert.Equal(LoginPath, PathOf(location));
        AssertCarriesTheStoredRequest(location);
    }

    [Fact]
    public async Task Prompt_select_account_sends_the_user_to_the_account_chooser()
    {
        var location = await InteractionRedirectAsync(CreateClientFor(factory), Prompts.SelectAccount);

        Assert.Equal(AccountSelectionPath, PathOf(location));
        AssertCarriesTheStoredRequest(location);
    }

    [Fact]
    public async Task Prompt_create_sends_the_user_to_registration()
    {
        var location = await InteractionRedirectAsync(CreateClientFor(factory), Prompts.Create);

        Assert.Equal(RegistrationPath, PathOf(location));
        AssertCarriesTheStoredRequest(location);
    }

    /// <summary>
    /// The consent destination is reached when the consent provider reports something still pending, which no
    /// prompt value can force on its own. The default host grants everything, so this one substitutes a
    /// provider that withholds consent for the requested scope.
    /// </summary>
    [Fact]
    public async Task A_pending_consent_sends_the_user_to_the_consent_page()
    {
        await using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Replace(ServiceDescriptor.Scoped<IUserConsentsProvider, WithholdingConsentsProvider>())));

        var location = await InteractionRedirectAsync(CreateClientFor(host), Prompts.Consent);

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
