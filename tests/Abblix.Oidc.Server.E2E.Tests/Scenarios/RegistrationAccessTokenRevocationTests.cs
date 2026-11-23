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
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A registration access token carries no expiry, and it is revoked at the revocation endpoint by the client it
/// manages: RFC 7009 section 2.1 has the token "not be used again after the revocation", so the client configuration
/// endpoint refuses it from then on.
/// </summary>
public class RegistrationAccessTokenRevocationTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task The_owner_revoking_its_registration_access_token_can_no_longer_read_with_it()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registration = await RegisterAsync(client, discovery);

        var revocation = await RevokeAsync(
            client, discovery, registration.AccessToken, registration.ClientId, registration.ClientSecret);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);

        var read = await ReadAsync(client, registration.ConfigurationUri, registration.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, read.StatusCode);
    }

    [Fact]
    public async Task Another_client_revoking_a_registration_access_token_leaves_it_working()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registration = await RegisterAsync(client, discovery);

        var revocation = await RevokeAsync(client, discovery, registration.AccessToken, TestConstants.EmptyAllowlistClientId);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);

        var read = await ReadAsync(client, registration.ConfigurationUri, registration.AccessToken);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
    }

    /// <summary>
    /// An update gives the client a new token and refuses the one it replaced (RFC 7592 section 2.2), so the replaced
    /// one is no longer valid and revoking it leaves the new one working.
    /// </summary>
    [Fact]
    public async Task The_owner_revoking_a_replaced_registration_access_token_leaves_the_current_one_working()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registration = await RegisterAsync(client, discovery);

        var update = new HttpRequestMessage(HttpMethod.Put, registration.ConfigurationUri);
        update.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, registration.AccessToken);
        var metadata = Metadata();
        metadata[RequestMembers.ClientId] = registration.ClientId;
        update.Content = JsonContent.Create(metadata);
        var updated = await client.SendAsync(update, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        var current = JsonNode.Parse(await updated.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!
            [ResponseMembers.RegistrationAccessToken]!.GetValue<string>();
        Assert.NotEqual(registration.AccessToken, current);

        var revocation = await RevokeAsync(
            client, discovery, registration.AccessToken, registration.ClientId, registration.ClientSecret);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);

        var read = await ReadAsync(client, registration.ConfigurationUri, current);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
    }

    private sealed record Registration(string ClientId, string ClientSecret, string AccessToken, Uri ConfigurationUri);

    /// <summary>
    /// A client authenticating with its secret in the request body, so the revocation request names it as the test
    /// clients are named.
    /// </summary>
    private static JsonObject Metadata() => new()
    {
        [RequestMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
        [RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
    };

    private static async Task<Registration> RegisterAsync(HttpClient client, DiscoveryDocument discovery)
    {
        var registered = await RegisterClientAsync(client, discovery, Metadata());
        return new Registration(
            registered[ResponseMembers.ClientId]!.GetValue<string>(),
            registered[ResponseMembers.ClientSecret]!.GetValue<string>(),
            registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>(),
            new Uri(registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>(), UriKind.RelativeOrAbsolute));
    }

    private static async Task<HttpResponseMessage> RevokeAsync(
        HttpClient client, DiscoveryDocument discovery, string token, string clientId, string clientSecret) =>
        await FormPostHelpers.PostFormAsync(client, discovery.RevocationEndpoint!, new Dictionary<string, string>
        {
            [RevocationRequest.Parameters.Token] = token,
            [ClientRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
        });

    private static async Task<HttpResponseMessage> ReadAsync(HttpClient client, Uri configurationUri, string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, configurationUri);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }
}
