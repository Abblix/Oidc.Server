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
using Abblix.Oidc.Server.Model;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 6749 section 4.4: the client credentials grant "MUST only be used by confidential clients", so neither a
/// registration nor an RFC 7592 update can give it to a client authenticating with none.
/// </summary>
public class ConfidentialGrantTypesTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task A_registration_of_a_public_client_with_client_credentials_is_refused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await client.PostAsJsonAsync(
            discovery.RegistrationEndpoint,
            PublicClientMetadata(GrantTypes.ClientCredentials),
            TestContext.Current.CancellationToken);

        await AssertInvalidClientMetadataAsync(response);
    }

    [Fact]
    public async Task An_update_giving_a_public_client_client_credentials_is_refused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = PublicClientMetadata(GrantTypes.AuthorizationCode);
        metadata[RequestMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code);
        metadata[RequestMembers.RedirectUris] = new JsonArray("https://client.example.com/callback");
        var registered = await RegisterClientAsync(client, discovery, metadata);

        metadata[RequestMembers.ClientId] = registered[ResponseMembers.ClientId]!.GetValue<string>();
        metadata[RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials);
        using var update = new HttpRequestMessage(
            HttpMethod.Put, registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>())
        {
            Content = JsonContent.Create(metadata),
        };
        update.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Bearer, registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>());
        using var response = await client.SendAsync(update, TestContext.Current.CancellationToken);

        await AssertInvalidClientMetadataAsync(response);
    }

    private static JsonObject PublicClientMetadata(string grantType) => new()
    {
        [RequestMembers.ClientName] = "public-client",
        [RequestMembers.GrantTypes] = new JsonArray(grantType),
        [RequestMembers.ResponseTypes] = new JsonArray(),
        [RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.None,
    };

    private static async Task AssertInvalidClientMetadataAsync(HttpResponseMessage response)
    {
        var body = JsonNode.Parse(
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode}");
        Assert.Equal(ErrorCodes.InvalidClientMetadata, body[ErrorResponse.Parameters.Error]!.GetValue<string>());
    }
}
