// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// How the endpoints that read a posted form treat a parameter sent more than once, the same on both hosts: RFC 6749
/// section 3.2 says "Request and response parameters MUST NOT be included more than once", and RFC 8707 lets
/// <c>resource</c> repeat.
/// </summary>
public class FormParameterReadingTests(TestFactory factory) : TestBase(factory)
{
    private const string UnregisteredResource = "https://unregistered.example.com/api";

    /// <summary>The token request the other rows add to, accepted as it stands.</summary>
    [Fact]
    public async Task TokenRequest_AsItStands_IsAccepted()
    {
        var (status, body) = await PostTokenAsync([]);

        Assert.True(status == HttpStatusCode.OK, body.ToJsonString());
    }

    [Theory]
    [InlineData(TokenRequest.Parameters.Scope, Scopes.OpenId)]
    [InlineData(TokenRequest.Parameters.GrantType, GrantTypes.ClientCredentials)]
    public async Task TokenParameter_SentTwice_IsRefused(string name, string value)
    {
        var (status, body) = await PostTokenAsync([new(name, value), new(name, value)]);

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(ErrorCodes.InvalidRequest, body[ResponseParameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// Every entry of a repeated resource is read: an unregistered one is refused wherever it stands.
    /// </summary>
    [Theory]
    [InlineData(TestConstants.ApiResource, UnregisteredResource)]
    [InlineData(UnregisteredResource, TestConstants.ApiResource)]
    public async Task Resource_SentTwice_EachEntryIsRead(string first, string second)
    {
        var (_, body) = await PostTokenAsync(
            [new(TokenRequest.Parameters.Resource, first), new(TokenRequest.Parameters.Resource, second)],
            withResource: false);

        Assert.Equal(ErrorCodes.InvalidTarget, body[ResponseParameters.Error]!.GetValue<string>());
    }

    [Fact]
    public async Task Audience_SentTwice_IsNotRefusedAsRepeated()
    {
        var (status, body) = await PostTokenAsync(
        [
            new(TokenRequest.Parameters.Audience, TestConstants.ApiResource),
            new(TokenRequest.Parameters.Audience, TestConstants.ApiResource),
        ]);

        Assert.True(status == HttpStatusCode.OK, body.ToJsonString());
    }

    [Fact]
    public async Task PushedParameter_SentTwice_IsRefused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (_, challenge) = GeneratePkcePair();
        KeyValuePair<string, string>[] form =
        [
            new(ClientRequest.Parameters.ClientId, TestConstants.ConfidentialClientId),
            new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
            new(AuthorizationRequest.Parameters.ResponseType, ResponseTypes.Code),
            new(AuthorizationRequest.Parameters.RedirectUri, TestConstants.RedirectUri),
            new(AuthorizationRequest.Parameters.Scope, Scopes.OpenId),
            new(AuthorizationRequest.Parameters.CodeChallenge, challenge),
            new(AuthorizationRequest.Parameters.CodeChallengeMethod, CodeChallengeMethods.S256),
            new(AuthorizationRequest.Parameters.State, "first"),
        ];

        var accepted = await FormPostHelpers.PostFormAsync(client, discovery.PushedAuthorizationRequestEndpoint!, form);
        var refused = await FormPostHelpers.PostFormAsync(
            client,
            discovery.PushedAuthorizationRequestEndpoint!,
            [.. form, new(AuthorizationRequest.Parameters.State, "second")]);

        Assert.True(accepted.IsSuccessStatusCode, await accepted.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequest, (await ReadJsonAsync(refused))[ResponseParameters.Error]!.GetValue<string>());
    }

    private async Task<(HttpStatusCode Status, JsonObject Body)> PostTokenAsync(
        KeyValuePair<string, string>[] added, bool withResource = true)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        List<KeyValuePair<string, string>> form =
        [
            new(TokenRequest.Parameters.GrantType, GrantTypes.ClientCredentials),
            new(ClientRequest.Parameters.ClientId, TestConstants.ClientCredentialsClientId),
            new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
        ];
        if (withResource)
            form.Add(new(TokenRequest.Parameters.Resource, TestConstants.ApiResource));
        form.AddRange(added);

        var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form);
        return (response.StatusCode, await ReadJsonAsync(response));
    }

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
}
