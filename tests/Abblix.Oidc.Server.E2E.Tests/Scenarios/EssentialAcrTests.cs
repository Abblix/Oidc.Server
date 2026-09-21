// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// An <c>acr</c> claim marked essential with the values it accepts is a requirement on the authentication,
/// not a preference: OpenID Connect Core 1.0 section 5.5.1.1 says the server "MUST return an acr Claim Value
/// that matches one of the requested values", "MAY ask the End-User to re-authenticate with additional
/// factors to meet this requirement", and where the requirement cannot be met "MUST treat that outcome as a
/// failed authentication attempt".
/// </summary>
/// <remarks>
/// Driven from out here because what the requirement costs is only visible at the endpoint: that the
/// validator is registered and constructed at all, that a refusal over it is delivered the way a client can
/// read, and that the session filter is what turns an unmet requirement into the login page rather than into
/// an answer nobody asked for.
/// <para>
/// Every case runs twice, inline and through <c>request_uri</c>, because the qualifier arrives as a
/// <see cref="JsonElement"/> on the first path and as a string after the pushed request was stored - the
/// distinction the shared qualifier reader exists for, and the one a single path would leave unproven.
/// </para>
/// </remarks>
public class EssentialAcrTests(TestFactory factory) : TestBase(factory)
{
    private const string Alice = "e2e-alice";
    private const string Loa1 = "urn:example:loa1";
    private const string Loa3 = "urn:example:loa3";
    private const string LoginPath = "/login";

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_level_no_session_holds_sends_the_user_to_the_login_page(bool throughRequestUri)
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAtLevel((Alice, Loa1));

        var location = await AuthorizeForInteractionAsync(
            client, discovery, RequiringLevels(Loa3), interactive: true, throughRequestUri);

        Assert.Equal(LoginPath, location.AbsolutePath);
    }

    /// <summary>
    /// The same request forbidding interaction is the failed authentication attempt the section requires, and
    /// the OpenID Foundation gives that outcome a code of its own rather than leaving it as
    /// <c>login_required</c>, which would send the client to retry what cannot change the answer.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_level_no_session_holds_and_no_interaction_is_refused(bool throughRequestUri)
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAtLevel((Alice, Loa1));

        var error = await AuthorizeAndExtractErrorAsync(
            client, discovery, await RequestAsync(client, discovery, RequiringLevels(Loa3), false, throughRequestUri));

        Assert.Equal(ErrorCodes.UnmetAuthenticationRequirements, error);
    }

    /// <summary>
    /// A single <c>value</c> requires a level as much as a one-member <c>values</c> does, which is what
    /// section 5.5.1 means by naming the two qualifiers together.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_single_requested_value_behaves_as_a_choice_of_one(bool throughRequestUri)
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAtLevel((Alice, Loa1));

        var error = await AuthorizeAndExtractErrorAsync(
            client, discovery, await RequestAsync(client, discovery, RequiringValue(Loa3), false, throughRequestUri));

        Assert.Equal(ErrorCodes.UnmetAuthenticationRequirements, error);
    }

    /// <summary>
    /// Qualifiers with no level in common accept nothing, so the request is refused as malformed rather than
    /// answered as a requirement nobody happens to meet - the same answer the requested end user gets. The
    /// session holds the level <c>value</c> names, so what refuses this is the contradiction and not the
    /// authentication.
    /// </summary>
    [Fact]
    public async Task Qualifiers_naming_no_common_level_are_an_invalid_request()
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAtLevel((Alice, Loa3));

        var error = await AuthorizeAndExtractErrorAsync(
            client,
            discovery,
            await RequestAsync(client, discovery, Contradictory(), false, throughRequestUri: false));

        Assert.Equal(ErrorCodes.InvalidRequest, error);
    }

    /// <summary>
    /// The same request pushed first never reaches the authorization endpoint: the pushed request endpoint
    /// runs the same validators and refuses it there, which is where a client that pushed finds out.
    /// </summary>
    [Fact]
    public async Task Qualifiers_naming_no_common_level_are_refused_when_the_request_is_pushed()
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAtLevel((Alice, Loa3));
        Assert.NotNull(discovery.PushedAuthorizationRequestEndpoint);

        var form = await RequestAsync(client, discovery, Contradictory(), false, throughRequestUri: false);
        form[ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret;

        var response = await client.PostAsync(
            discovery.PushedAuthorizationRequestEndpoint,
            new FormUrlEncodedContent(form),
            TestContext.Current.CancellationToken);

        var body = JsonNode.Parse(
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequest, body["error"]!.GetValue<string>());
    }

    /// <summary>A request whose two qualifiers accept no level at all.</summary>
    private static string Contradictory() => JsonSerializer.Serialize(
        new { id_token = new { acr = new { essential = true, value = Loa3, values = new[] { Loa1 } } } });

    /// <summary>
    /// A requirement the session does meet is answered without asking anybody to sign in again, and the ID
    /// Token states the level that satisfied it.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_level_the_session_holds_completes_and_the_token_states_it(bool throughRequestUri)
    {
        await using var host = CreateHost(out var sessions);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        sessions.SignedInAtLevel((Alice, Loa3));

        var (verifier, challenge) = GeneratePkcePair();
        var request = await RequestAsync(
            client, discovery, RequiringLevels(Loa1, Loa3), false, throughRequestUri, challenge);

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, request);
        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var idToken = tokens[ResponseParameters.IdToken]!.GetValue<string>();
        Assert.Equal(Loa3, DecodeJwtPayload(idToken)[IanaClaimTypes.Acr]!.GetValue<string>());
    }

    private static string RequiringLevels(params string[] levels) =>
        JsonSerializer.Serialize(new { id_token = new { acr = new { essential = true, values = levels } } });

    private static string RequiringValue(string level) =>
        JsonSerializer.Serialize(new { id_token = new { acr = new { essential = true, value = level } } });

    /// <summary>
    /// Builds the authorization request, either carrying the claims parameter itself or pushing it first and
    /// carrying the <c>request_uri</c> the server hands back.
    /// </summary>
    private static async Task<Dictionary<string, string>> RequestAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string claims,
        bool interactive,
        bool throughRequestUri,
        string? codeChallenge = null)
    {
        var (_, challenge) = GeneratePkcePair();
        var parameters = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = codeChallenge ?? challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            [AuthorizationRequest.Parameters.Claims] = claims,
        };

        if (!interactive)
            parameters[AuthorizationRequest.Parameters.Prompt] = Prompts.None;

        if (!throughRequestUri)
            return parameters;

        var pushed = await PushAsync(client, discovery, parameters);
        return new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.RequestUri] = pushed,
        };
    }

    private static async Task<string> PushAsync(
        HttpClient client, DiscoveryDocument discovery, Dictionary<string, string> parameters)
    {
        Assert.NotNull(discovery.PushedAuthorizationRequestEndpoint);

        var form = new Dictionary<string, string>(parameters)
        {
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        };

        var response = await client.PostAsync(
            discovery.PushedAuthorizationRequestEndpoint,
            new FormUrlEncodedContent(form),
            TestContext.Current.CancellationToken);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"pushing the request failed: {(int)response.StatusCode} {body}");

        return JsonNode.Parse(body)!["request_uri"]!.GetValue<string>();
    }

    private static async Task<Uri> AuthorizeForInteractionAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string claims,
        bool interactive,
        bool throughRequestUri)
    {
        var parameters = await RequestAsync(client, discovery, claims, interactive, throughRequestUri);
        var uri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters);

        var response = await client.GetAsync(uri, TestContext.Current.CancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"/authorize answered {(int)response.StatusCode}, expected a redirect. Body: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        return response.Headers.Location
               ?? throw new InvalidOperationException("/authorize redirected without a Location header");
    }

    private WebApplicationFactory<Program> CreateHost(out MutableAuthSessionService sessions)
    {
        var stub = new MutableAuthSessionService(TimeProvider.System);
        sessions = stub;

        return Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Replace(ServiceDescriptor.Singleton<IAuthSessionService>(stub))));
    }

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
}
