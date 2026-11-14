// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Model;
using Xunit;
using RegistrationRequest = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using RegistrationResponse = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A request field that happens to carry the name of an MVC action's parameter, such as <c>tokenRequest</c>, is a
/// parameter the server does not recognize. RFC 6749 sections 3.1 and 3.2, for the authorization and the token
/// endpoint: "The authorization server MUST ignore unrecognized request parameters", so each endpoint answers the
/// request with that field as it answers the request without it.
/// </summary>
/// <remarks>
/// The field names below are the parameter names of the library's MVC actions. The Minimal API host has no such
/// names and answers every row as the plain request; the rows are shared so both hosts are held to the same answer.
/// The backchannel authentication rows live with the scenarios that build a host able to start one.
/// </remarks>
public class ActionParameterNamedFieldTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData("tokenRequest")]
    [InlineData("clientRequest")]
    public async Task Token_request_with_a_field_named_after_an_action_parameter_is_answered_as_without_it(
        string field)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        await AssertAnsweredAsWithoutAsync(
            form => FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form),
            new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
                [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
                [ClientRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            },
            field,
            HttpStatusCode.OK);
    }

    [Theory]
    [InlineData("revocationRequest")]
    [InlineData("clientRequest")]
    public async Task Revocation_request_with_a_field_named_after_an_action_parameter_is_answered_as_without_it(
        string field)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.RevocationEndpoint);

        await AssertAnsweredAsWithoutAsync(
            form => FormPostHelpers.PostFormAsync(client, discovery.RevocationEndpoint, form),
            ConfidentialClientForm(new() { [RevocationRequest.Parameters.Token] = "any" }),
            field,
            HttpStatusCode.OK);
    }

    [Theory]
    [InlineData("introspectionRequest")]
    [InlineData("clientRequest")]
    public async Task Introspection_request_with_a_field_named_after_an_action_parameter_is_answered_as_without_it(
        string field)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.IntrospectionEndpoint);

        await AssertAnsweredAsWithoutAsync(
            form => FormPostHelpers.PostFormAsync(client, discovery.IntrospectionEndpoint, form),
            ConfidentialClientForm(new() { [IntrospectionRequest.Parameters.Token] = "any" }),
            field,
            HttpStatusCode.OK);
    }

    [Theory]
    [InlineData("authorizationRequest")]
    [InlineData("clientRequest")]
    public async Task Pushed_authorization_request_with_a_field_named_after_an_action_parameter_is_answered_as_without_it(
        string field)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.PushedAuthorizationRequestEndpoint);
        var (_, challenge) = GeneratePkcePair();

        await AssertAnsweredAsWithoutAsync(
            form => FormPostHelpers.PostFormAsync(client, discovery.PushedAuthorizationRequestEndpoint, form),
            ConfidentialClientForm(CodeFlowParameters(TestConstants.ConfidentialClientId, challenge)),
            field,
            HttpStatusCode.Created);
    }

    /// <summary>
    /// Every field of a device authorization request may be absent, so the request names a resource the client may
    /// not have: refused when it is read, and answered with a code if a field hid it.
    /// </summary>
    [Theory]
    [InlineData("deviceAuthorizationRequest")]
    [InlineData("clientRequest")]
    public async Task Device_authorization_request_with_a_field_named_after_an_action_parameter_is_answered_as_without_it(
        string field)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.DeviceAuthorizationEndpoint);

        // A device client has no user agent to redirect, so it declares no response type
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationRequest.ClientName] = $"named-field-{Guid.NewGuid():N}",
            [RegistrationRequest.GrantTypes] = new JsonArray(GrantTypes.DeviceAuthorization),
            [RegistrationRequest.ResponseTypes] = new JsonArray(),
            [RegistrationRequest.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
        });

        await AssertAnsweredAsWithoutAsync(
            form => FormPostHelpers.PostFormAsync(client, discovery.DeviceAuthorizationEndpoint, form),
            new Dictionary<string, string>
            {
                [DeviceAuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
                [DeviceAuthorizationRequest.Parameters.Resource] = "https://unregistered.example.com/api",
                [ClientRequest.Parameters.ClientId] = registered[RegistrationResponse.ClientId]!.GetValue<string>(),
                [ClientRequest.Parameters.ClientSecret] = registered[RegistrationResponse.ClientSecret]!.GetValue<string>(),
            },
            field,
            HttpStatusCode.BadRequest);
    }

    /// <summary>
    /// The authorization endpoint reads the query, so the field arrives there.
    /// </summary>
    [Fact]
    public async Task Authorization_request_with_a_field_named_after_its_action_parameter_is_answered_as_without_it()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (_, challenge) = GeneratePkcePair();

        await AssertAnsweredAsWithoutAsync(
            query => client.GetAsync(QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, query)),
            CodeFlowParameters(TestConstants.ConfidentialClientId, challenge),
            "authorizationRequest",
            HttpStatusCode.SeeOther);
    }

    /// <summary>
    /// The userinfo request reads no client field, so only the name of its own model is a row here.
    /// </summary>
    [Fact]
    public async Task UserInfo_request_with_a_field_named_after_its_action_parameter_is_answered_as_without_it()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.UserInfoEndpoint);
        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);

        await AssertAnsweredAsWithoutAsync(
            form => FormPostHelpers.PostFormAsync(client, discovery.UserInfoEndpoint, form),
            new Dictionary<string, string>
            {
                [UserInfoRequest.Parameters.AccessToken] = tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>(),
            },
            "userInfoRequest",
            HttpStatusCode.OK);
    }

    /// <summary>
    /// A logout request carrying an id_token_hint that is no token is refused for it; a field hiding the hint would
    /// turn the answer into a request for the end user's confirmation.
    /// </summary>
    [Fact]
    public async Task End_session_request_with_a_field_named_after_its_action_parameter_is_answered_as_without_it()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.EndSessionEndpoint);

        await AssertAnsweredAsWithoutAsync(
            query => client.GetAsync(QueryHelpers.BuildUri(discovery.EndSessionEndpoint, query)),
            new Dictionary<string, string>
            {
                [EndSessionRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [EndSessionRequest.Parameters.IdTokenHint] = "not-a-token",
            },
            "request",
            HttpStatusCode.BadRequest);
    }

    /// <summary>
    /// The client configuration endpoint (RFC 7592 section 2) reads the client from the path and the token from the
    /// header, and a query field named after the action's parameter is still a field of the request.
    /// </summary>
    [Theory]
    [InlineData("GET", HttpStatusCode.OK)]
    [InlineData("PUT", HttpStatusCode.OK)]
    [InlineData("DELETE", HttpStatusCode.NoContent)]
    public async Task Client_configuration_request_with_a_query_field_named_after_its_action_parameter_is_answered(
        string method, HttpStatusCode expected)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationRequest.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
        });
        var clientId = registered[RegistrationResponse.ClientId]!.GetValue<string>();
        var configurationUri = new Uri(
            registered[RegistrationResponse.RegistrationClientUri]!.GetValue<string>(), UriKind.RelativeOrAbsolute);

        using var request = new HttpRequestMessage(
            new HttpMethod(method),
            QueryHelpers.BuildUri(configurationUri, new Dictionary<string, string> { ["authorizationRequest"] = "1" }));
        request.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Bearer, registered[RegistrationResponse.RegistrationAccessToken]!.GetValue<string>());
        if (method == HttpMethod.Put.Method)
        {
            request.Content = JsonContent.Create(new JsonObject
            {
                [RegistrationRequest.ClientId] = clientId,
                [RegistrationRequest.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            });
        }

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == expected, $"{(int)response.StatusCode}: {raw}");
    }

    private static Dictionary<string, string> ConfidentialClientForm(Dictionary<string, string> parameters)
        => new(parameters)
        {
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        };
}
