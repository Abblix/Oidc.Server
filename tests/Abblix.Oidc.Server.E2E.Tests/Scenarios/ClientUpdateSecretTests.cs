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
/// RFC 7592 section 2.2: "If the client includes the "client_secret" field in the request, the value of this field
/// MUST match the currently issued client secret for that client", so an update carrying another secret is refused
/// with invalid_client_metadata, and one carrying the issued secret is applied.
/// </summary>
public class ClientUpdateSecretTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData(false, HttpStatusCode.BadRequest)]
    [InlineData(true, HttpStatusCode.OK)]
    public async Task An_update_is_applied_only_with_the_secret_issued(bool issuedSecret, HttpStatusCode expected)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = new JsonObject
        {
            [RequestMembers.ClientName] = "update-secret",
            [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.ClientCredentials),
            [RequestMembers.ResponseTypes] = new JsonArray(),
            [RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretBasic,
        };
        var registered = await RegisterClientAsync(client, discovery, metadata);

        metadata[RequestMembers.ClientId] = registered[ResponseMembers.ClientId]!.GetValue<string>();
        metadata[RequestMembers.ClientSecret] = issuedSecret
            ? registered[ResponseMembers.ClientSecret]!.GetValue<string>()
            : "a-secret-the-client-chose";
        using var update = new HttpRequestMessage(
            HttpMethod.Put, registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>())
        {
            Content = JsonContent.Create(metadata),
        };
        update.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Bearer, registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>());
        using var response = await client.SendAsync(update, TestContext.Current.CancellationToken);
        var body = JsonNode.Parse(
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

        Assert.True(response.StatusCode == expected, $"{(int)response.StatusCode}: {body}");
        if (expected == HttpStatusCode.BadRequest)
            Assert.Equal(ErrorCodes.InvalidClientMetadata, body[ErrorResponse.Parameters.Error]!.GetValue<string>());
    }
}
