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

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Json;
using System.Net.Mime;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Net.Http.Headers;
using EndSessionParameters = Abblix.Oidc.Server.Model.EndSessionRequest.Parameters;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// The Minimal API counterpart of the MVC suite's RP-initiated logout scenarios: every shape the end-session
/// endpoint can answer with - a framed page, a redirect, a refusal, and 204 when there is nowhere to return to
/// (OpenID Connect RP-Initiated Logout 1.0, and Front-Channel Logout 1.0 section 2 for the framed page).
/// </summary>
/// <remarks>
/// The endpoint was reached here only by a binding test, which proves the parameters arrive and says nothing
/// about what comes back. Each answer is a separate arm of one formatter, and the adapters implement that
/// formatter separately, so this pins the Minimal API side against the same cases as the MVC one.
/// </remarks>
public sealed class EndSessionTests(TestFactory factory) : IClassFixture<TestFactory>
{
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test post_logout_redirect_uri for the dynamically registered client; not a deployment URL.")]
    private const string RegisteredPostLogoutUri = "https://client.example.com/after-logout";

    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Stand-in for an attacker-controlled target in the open-redirect test; not a deployment URL.")]
    private const string UnregisteredPostLogoutUri = "https://attacker.example.com/harvest";

    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test frontchannel_logout_uri for the dynamically registered client; not a deployment URL.")]
    private static readonly Uri FrontChannelLogoutUri = new("https://client.example.com/front-channel-logout");

    private HttpClient CreateClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        BaseAddress = TestFactory.BaseAddress,
    });

    /// <summary>
    /// A client that registered a front-channel logout URI is signed out through a browser page that frames
    /// that URI, so the client's own site clears its cookies. The page deliberately frames a third party, which
    /// makes its Content-Security-Policy the only thing bounding what it may load.
    /// </summary>
    [Fact]
    public async Task A_client_with_a_front_channel_logout_uri_is_signed_out_through_a_framed_page()
    {
        // On its own host: authorizing adds this client to the session the test host keeps for the whole
        // process, and that addition never goes away - a shared host would hand every later end-session test a
        // client to notify through the front channel, turning their redirects into this page.
        await using var host = factory.WithWebHostBuilder(_ => { });
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestFactory.BaseAddress,
        });

        var discovery = await client.FetchDiscoveryAsync();
        var (clientId, clientSecret) = await RegisterAsync(client, discovery, frontChannelLogout: true);

        // Authorizing is what ties the client to the session; without it the OP has nobody to notify.
        await client.AuthCodeTokensViaParAsync(discovery, clientId, clientSecret);

        var response = await EndSessionAsync(client, discovery, new Dictionary<string, string>
        {
            [EndSessionParameters.ClientId] = clientId,
            [EndSessionParameters.PostLogoutRedirectUri] = RegisteredPostLogoutUri,
            [EndSessionParameters.Confirmed] = bool.TrueString,
        });

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"/end_session failed: {(int)response.StatusCode} {body}");
        Assert.Equal(MediaTypeNames.Text.Html, response.Content.Headers.ContentType?.MediaType);
        Assert.Contains(FrontChannelLogoutUri.OriginalString, body);

        var policy = response.Headers.GetValues(HeaderNames.ContentSecurityPolicy).Single();

        // A policy names origins rather than paths, so the origin is what is asserted here.
        Assert.Contains("default-src 'none'", policy);
        Assert.Contains(FrontChannelLogoutUri.GetLeftPart(UriPartial.Authority), policy);
        Assert.DoesNotContain("frame-src *", policy);
    }

    /// <summary>
    /// With nobody to notify through the front channel, the user agent is simply sent to the landing page the
    /// client registered.
    /// </summary>
    [Fact]
    public async Task A_registered_post_logout_redirect_uri_is_honoured()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var (clientId, _) = await RegisterAsync(client, discovery, frontChannelLogout: false);

        var response = await EndSessionAsync(client, discovery, new Dictionary<string, string>
        {
            [EndSessionParameters.ClientId] = clientId,
            [EndSessionParameters.PostLogoutRedirectUri] = RegisteredPostLogoutUri,
            [EndSessionParameters.Confirmed] = bool.TrueString,
        });

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.Equal(RegisteredPostLogoutUri, response.Headers.Location.GetLeftPart(UriPartial.Path));
    }

    /// <summary>
    /// The end-session endpoint takes a redirect target from whoever calls it, which makes it the one place in
    /// the protocol where an unauthenticated URI decides where the browser lands. A target the client never
    /// registered is refused with the protocol's own error, not honoured.
    /// </summary>
    [Fact]
    public async Task A_post_logout_redirect_uri_the_client_never_registered_is_refused()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var (clientId, _) = await RegisterAsync(client, discovery, frontChannelLogout: false);

        var response = await EndSessionAsync(client, discovery, new Dictionary<string, string>
        {
            [EndSessionParameters.ClientId] = clientId,
            [EndSessionParameters.PostLogoutRedirectUri] = UnregisteredPostLogoutUri,
            [EndSessionParameters.Confirmed] = bool.TrueString,
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = JsonNode.Parse(
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

        Assert.Equal(
            ErrorCodes.InvalidRequest,
            body[ResponseParameters.Error]?.GetValue<string>());

        // The refusal must not name the rejected target as somewhere to go: no redirect, whatever the body says.
        Assert.Null(response.Headers.Location);
    }

    /// <summary>
    /// A logout with nowhere to return to and nobody to notify answers 204: no body, no redirect. RP-Initiated
    /// Logout 1.0 makes <c>post_logout_redirect_uri</c> optional, so this is what an ordinary client that does
    /// not ask to be sent anywhere receives.
    /// </summary>
    [Fact]
    public async Task A_logout_with_nowhere_to_return_to_answers_no_content()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var (clientId, _) = await RegisterAsync(client, discovery, frontChannelLogout: false);

        var response = await EndSessionAsync(client, discovery, new Dictionary<string, string>
        {
            [EndSessionParameters.ClientId] = clientId,
            [EndSessionParameters.Confirmed] = bool.TrueString,
        });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private static async Task<(string ClientId, string ClientSecret)> RegisterAsync(
        HttpClient client, JsonObject discovery, bool frontChannelLogout)
    {
        var metadata = new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [RegistrationMembers.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
            [RegistrationMembers.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
            [RegistrationMembers.PostLogoutRedirectUris] = new JsonArray { RegisteredPostLogoutUri },
        };

        if (frontChannelLogout)
            metadata[RegistrationMembers.FrontChannelLogoutUri] = FrontChannelLogoutUri.OriginalString;

        var endpoint = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.RegistrationEndpoint);
        var response = await client.PostAsJsonAsync(endpoint, metadata, TestContext.Current.CancellationToken);

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"registration failed: {(int)response.StatusCode} {raw}");

        var registered = JsonNode.Parse(raw)!.AsObject();
        return (
            registered[ClientRequest.Parameters.ClientId]!.GetValue<string>(),
            registered[ClientRequest.Parameters.ClientSecret]!.GetValue<string>());
    }

    private static async Task<HttpResponseMessage> EndSessionAsync(
        HttpClient client, JsonObject discovery, Dictionary<string, string> query)
    {
        var endpoint = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.EndSessionEndpoint);
        return await client.GetAsync(OidcFlows.BuildQuery(endpoint, query), TestContext.Current.CancellationToken);
    }
}
