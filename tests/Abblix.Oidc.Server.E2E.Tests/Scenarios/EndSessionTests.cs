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
using System.Net.Mime;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Net.Http.Headers;
using Xunit;
using EndSessionParameters = Abblix.Oidc.Server.Model.EndSessionRequest.Parameters;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using RegistrationResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0) through the MVC adapter,
/// driven against the real end-session endpoint.
/// </summary>
/// <remarks>
/// The endpoint is live in the test host but nothing walked it, so the whole logout leg went unexercised.
/// The property under test is where the user agent lands afterwards, not what the response looks like.
/// The end-session endpoint takes a URI from whoever calls it and sends the browser there, which makes it the
/// one place in the protocol where a redirect target arrives unauthenticated. If the server honours a target
/// the client never registered, a trusted issuer domain becomes a bounce pad to an attacker's page, and the
/// user reaches it having just been shown a real logout on a real domain.
///
/// None of the statically configured clients in the test host register a post_logout_redirect_uri, so these
/// tests mint their own client through dynamic registration. That keeps the registered set explicit in the
/// test and leaves the shared host configuration alone.
/// </remarks>
public class EndSessionTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>The post-logout landing page the test client registers, and the only one it may be sent to.</summary>
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test post_logout_redirect_uri for the dynamically registered client; not a deployment URL.")]
    private const string RegisteredPostLogoutUri = "https://client.example.com/after-logout";

    /// <summary>A target the client never registered, standing in for whatever an attacker would name.</summary>
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Stand-in for an attacker-controlled target in the open-redirect test; not a deployment URL.")]
    private const string UnregisteredPostLogoutUri = "https://attacker.example.com/harvest";

    /// <summary>The client's own logout endpoint, which the OP's page loads in a frame.</summary>
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test frontchannel_logout_uri for the dynamically registered client; not a deployment URL.")]
    private static readonly Uri FrontChannelLogoutUri = new("https://client.example.com/front-channel-logout");

    [Fact]
    public async Task A_post_logout_redirect_uri_the_client_never_registered_is_refused()
    {
        // The open-redirect boundary. The end-session endpoint accepts a redirect target from an unauthenticated
        // caller, so anyone can craft a logout link on the issuer's own domain. If the server followed the target
        // it was handed, that link would carry the user from a genuine logout straight to a page the attacker
        // controls, with the issuer's domain in the address bar right up to the jump - the setup a credential
        // harvesting page wants. The registered set is the only thing standing between the two.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var clientId = await RegisterLogoutClientAsync(client, discovery);

        var response = await EndSessionAsync(client, discovery, new Dictionary<string, string>
        {
            [EndSessionParameters.ClientId] = clientId,
            [EndSessionParameters.PostLogoutRedirectUri] = UnregisteredPostLogoutUri,
            [EndSessionParameters.Confirmed] = bool.TrueString,
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // The status alone is not the property: a redirect that also answered 400 would still move the browser.
        Assert.Null(response.Headers.Location);

        var body = await ReadJsonAsync(response);
        Assert.Equal(ErrorCodes.InvalidRequest, body[ResponseParameters.Error]!.GetValue<string>());
    }

    [Fact]
    public async Task A_registered_post_logout_redirect_uri_is_honoured()
    {
        // Proving the accept side, so the rejection above means something. Without this, a server that redirected
        // nowhere at all - endpoint broken, logout leg dead - would pass the open-redirect test just as happily,
        // and the suite would report a security property it never checked.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var clientId = await RegisterLogoutClientAsync(client, discovery);

        var response = await EndSessionAsync(client, discovery, new Dictionary<string, string>
        {
            [EndSessionParameters.ClientId] = clientId,
            [EndSessionParameters.PostLogoutRedirectUri] = RegisteredPostLogoutUri,
            [EndSessionParameters.Confirmed] = bool.TrueString,
        });

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = AssertRedirectedTo(response, RegisteredPostLogoutUri);

        // Nothing was asked to be echoed, so nothing should be appended.
        Assert.Empty(location.Query);
    }

    [Fact]
    public async Task State_is_echoed_back_to_the_post_logout_redirect_target()
    {
        // State is how the client tells its own logout apart from one somebody else started. The landing page is
        // a plain GET that anyone can request directly, so without the value it sent back in hand the client has
        // to take the arrival on faith and clear the session for whoever knocks. That is a logout CSRF: an
        // attacker-embedded link signs the user out repeatedly, and worse, a forged arrival is indistinguishable
        // from a real one at exactly the moment the client is deciding what local state to tear down.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var clientId = await RegisterLogoutClientAsync(client, discovery);

        var state = Guid.NewGuid().ToString("N");
        var response = await EndSessionAsync(client, discovery, new Dictionary<string, string>
        {
            [EndSessionParameters.ClientId] = clientId,
            [EndSessionParameters.PostLogoutRedirectUri] = RegisteredPostLogoutUri,
            [EndSessionParameters.State] = state,
            [EndSessionParameters.Confirmed] = bool.TrueString,
        });

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = AssertRedirectedTo(response, RegisteredPostLogoutUri);

        var echoed = System.Web.HttpUtility.ParseQueryString(location.Query)[EndSessionParameters.State];
        Assert.Equal(state, echoed);
    }

    [Fact]
    public async Task The_end_session_endpoint_is_published_in_discovery()
    {
        // A relying party wires up its logout button from discovery metadata. An endpoint that is served but
        // unadvertised is one no conforming client will ever call, which leaves sessions alive on the OP after
        // the user believes they signed out.
        var discovery = await FetchDiscoveryAsync(CreateClient());

        Assert.NotNull(discovery.EndSessionEndpoint);
    }

    /// <summary>
    /// A client that registered a front-channel logout URI is signed out through a browser page rather than a
    /// redirect: the OP answers HTML that loads that URI in a frame, so the client's own site clears its
    /// cookies (OpenID Connect Front-Channel Logout 1.0 section 2).
    /// </summary>
    /// <remarks>
    /// This arm had no test through either adapter, and the thing it emits is a page that deliberately frames
    /// third-party URLs - so its Content-Security-Policy is the only thing standing between "load the logout
    /// endpoints of the clients in this session" and "load whatever the page happens to contain". A missing or
    /// weakened policy here would not fail any other assertion, because the logout still works.
    ///
    /// The client only receives a front-channel notice if the session knows it, which happens when it
    /// authorizes - so the flow runs first, and the logout follows on the same client.
    /// </remarks>
    [Fact]
    public async Task A_client_with_a_front_channel_logout_uri_is_signed_out_through_a_framed_page()
    {
        // On its own host: authorizing adds this client to the session the test host keeps for the whole
        // process, and that addition never goes away - a shared host would hand every later end-session test a
        // client to notify through the front channel, turning their redirects into this page.
        await using var host = Factory.WithWebHostBuilder(_ => { });
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

        var discovery = await FetchDiscoveryAsync(client);
        var clientId = await RegisterFrontChannelLogoutClientAsync(client, discovery);

        // Authorizing is what ties the client to the session; without it the OP has nobody to notify.
        var (_, challenge) = GeneratePkcePair();
        await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        });

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

        // The page frames a third party, so the policy has to name that origin and nothing wider, and it has to
        // deny everything it does not name - "default-src 'none'" is what makes the rest of it a whitelist.
        // A policy names origins rather than paths, so the origin is what is asserted here.
        Assert.Contains("default-src 'none'", policy);
        Assert.Contains(FrontChannelLogoutUri.GetLeftPart(UriPartial.Authority), policy);
        Assert.DoesNotContain("frame-src *", policy);
    }

    /// <summary>
    /// Registers a client that additionally asks to be signed out through the front channel.
    /// </summary>
    private static async Task<string> RegisterFrontChannelLogoutClientAsync(
        HttpClient client, DiscoveryDocument discovery)
    {
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationMembers.ClientName] = "front-channel-logout-rp",
            [RegistrationMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            [RegistrationMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode),
            [RegistrationMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code),
            [RegistrationMembers.PostLogoutRedirectUris] = new JsonArray(RegisteredPostLogoutUri),
            [RegistrationMembers.FrontChannelLogoutUri] = FrontChannelLogoutUri.OriginalString,
        });

        return registered[RegistrationResponseMembers.ClientId]!.GetValue<string>();
    }

    /// <summary>
    /// Registers a fresh client whose only registered post-logout landing page is
    /// <see cref="RegisteredPostLogoutUri"/>, and returns its client_id.
    /// </summary>
    private static async Task<string> RegisterLogoutClientAsync(HttpClient client, DiscoveryDocument discovery)
    {
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationMembers.ClientName] = "end-session-rp",
            [RegistrationMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            [RegistrationMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode),
            [RegistrationMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code),
            [RegistrationMembers.PostLogoutRedirectUris] = new JsonArray(RegisteredPostLogoutUri),
        });

        return registered[RegistrationResponseMembers.ClientId]!.GetValue<string>();
    }

    private static async Task<HttpResponseMessage> EndSessionAsync(
        HttpClient client, DiscoveryDocument discovery, Dictionary<string, string> queryParams)
    {
        Assert.NotNull(discovery.EndSessionEndpoint);
        var uri = QueryHelpers.BuildUri(discovery.EndSessionEndpoint!, queryParams);
        return await client.GetAsync(uri, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Asserts the response redirects to <paramref name="expectedTarget"/> ignoring any query the OP appended,
    /// and returns the parsed Location so the caller can inspect that query.
    /// </summary>
    private static Uri AssertRedirectedTo(HttpResponseMessage response, string expectedTarget)
    {
        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal(expectedTarget, location.GetLeftPart(UriPartial.Path));
        return location;
    }

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
}
