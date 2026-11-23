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
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 7592 section 3: a read "MUST return all registered metadata about this client", and Appendix A.1: "The client's
/// current registration access token and client credentials (if applicable) MUST be included in the client information
/// response". A tenant with a client secret encryption key returns the secret it issued at registration on a read and
/// an update alike; a tenant without one answers without it.
/// </summary>
public class ClientReadSecretTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task A_tenant_with_the_key_returns_the_issued_secret_on_read_and_update()
    {
        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.PostConfigure<TestTenantSettings>(tenant => tenant.ClientSecretEncryption =
                new ClientSecretEncryptionSettings { Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) })));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

        var (registered, metadata) = await RegisterAsync(client);
        var issued = registered[ResponseMembers.ClientSecret]!.GetValue<string>();

        var read = await SendAsync(client, registered, HttpMethod.Get, content: null);
        Assert.Equal(issued, read[ResponseMembers.ClientSecret]?.GetValue<string>());

        metadata[RequestMembers.ClientId] = registered[ResponseMembers.ClientId]!.GetValue<string>();
        var updated = await SendAsync(
            client, read, HttpMethod.Put, JsonContent.Create(metadata), registered[ResponseMembers.RegistrationClientUri]);
        Assert.Equal(issued, updated[ResponseMembers.ClientSecret]?.GetValue<string>());
    }

    [Fact]
    public async Task A_tenant_without_the_key_reads_without_the_secret()
    {
        var client = CreateClient();
        var (registered, _) = await RegisterAsync(client);

        var read = await SendAsync(client, registered, HttpMethod.Get, content: null);

        Assert.False(read.ContainsKey(ResponseMembers.ClientSecret));
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
