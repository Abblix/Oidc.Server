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
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 7592 section 3: a read "MUST return all registered metadata about this client", and Appendix A.1: "The client's
/// current registration access token and client credentials (if applicable) MUST be included in the client information
/// response". A server serving registration holds the client secret encryption key of every tenant, so the secret
/// issued at registration is returned on a read and an update alike.
/// </summary>
public class ClientReadSecretTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task The_issued_secret_is_returned_on_read_and_update()
    {
        var client = CreateClient();
        var (registered, metadata) = await RegisterAsync(client);
        var issued = registered[ResponseMembers.ClientSecret]!.GetValue<string>();

        var read = await SendAsync(client, registered, HttpMethod.Get, content: null);
        Assert.Equal(issued, read[ResponseMembers.ClientSecret]?.GetValue<string>());

        metadata[RequestMembers.ClientId] = registered[ResponseMembers.ClientId]!.GetValue<string>();
        var updated = await SendAsync(
            client, read, HttpMethod.Put, JsonContent.Create(metadata), registered[ResponseMembers.RegistrationClientUri]);
        Assert.Equal(issued, updated[ResponseMembers.ClientSecret]?.GetValue<string>());
    }

    private static async Task<(JsonObject Registered, JsonObject Metadata)> RegisterAsync(HttpClient client)
    {
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = new JsonObject
        {
            [RequestMembers.ClientName] = "read-secret",
            [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.ClientCredentials),
            [RequestMembers.ResponseTypes] = new JsonArray(),
            [RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretBasic,
        };
        return (await RegisterClientAsync(client, discovery, metadata), metadata);
    }

    /// <summary>
    /// Sends a request to the client configuration endpoint with the registration access token
    /// <paramref name="tokenHolder"/> carries, at the address it names or <paramref name="uri"/>.
    /// </summary>
    private static async Task<JsonObject> SendAsync(
        HttpClient client, JsonObject tokenHolder, HttpMethod method, HttpContent? content, JsonNode? uri = null)
    {
        using var request = new HttpRequestMessage(
            method, (uri ?? tokenHolder[ResponseMembers.RegistrationClientUri])!.GetValue<string>())
        {
            Content = content,
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Bearer, tokenHolder[ResponseMembers.RegistrationAccessToken]!.GetValue<string>());
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode}: {raw}");
        return JsonNode.Parse(raw)!.AsObject();
    }
}
