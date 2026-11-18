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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A host limiting the grant types of dynamically registered clients keeps registration, and the RFC 7592 update of a
/// registration, to that set, while a client within it registers as before; a host setting no limit admits every grant
/// type the server supports.
/// </summary>
public sealed class AllowedGrantTypesTests(TestFactory factory) : TestBase(factory)
{
    private const string ErrorMember = ErrorResponse.Parameters.Error;

    private static JsonObject SignInClientMetadata(string clientName) => new()
    {
        [RequestMembers.ClientName] = clientName,
        [RequestMembers.RedirectUris] = new JsonArray("https://client.example.com/callback"),
        [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken),
        [RequestMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code),
    };

    private static JsonObject MachineClientMetadata(string clientName) => new()
    {
        [RequestMembers.ClientName] = clientName,
        [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.ClientCredentials),
        [RequestMembers.ResponseTypes] = new JsonArray(),
    };

    private WebApplicationFactory<Program> SignInOnlyHost()
        => Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(
            services => services.PostConfigure<OidcOptions>(options => options.NewClientOptions =
                options.NewClientOptions with
                {
                    AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
                })));

    private static HttpClient ClientOf(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    [Fact]
    public async Task Without_a_limit_a_client_credentials_client_registers()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var registered = await RegisterClientAsync(client, discovery, MachineClientMetadata("machine-unlimited"));

        Assert.Equal(
            GrantTypes.ClientCredentials,
            Assert.Single(registered[RequestMembers.GrantTypes]!.AsArray())!.GetValue<string>());
    }

    [Fact]
    public async Task A_grant_type_outside_the_limit_is_refused_at_registration()
    {
        await using var host = SignInOnlyHost();
        var client = ClientOf(host);
        var discovery = await FetchDiscoveryAsync(client);

        var response = await client.PostAsJsonAsync(
            discovery.RegistrationEndpoint!,
            MachineClientMetadata("machine-limited"),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, await ReadErrorAsync(response));
    }

    /// <summary>
    /// A sign-in client within the limit registers with the <c>code</c> response type its authorization code grant
    /// pairs with, and an RFC 7592 update adding a grant type outside the limit is refused as a registration is, while
    /// the same update within the limit is served.
    /// </summary>
    [Fact]
    public async Task A_client_within_the_limit_registers_and_cannot_widen_it_on_update()
    {
        await using var host = SignInOnlyHost();
        var client = ClientOf(host);
        var discovery = await FetchDiscoveryAsync(client);
        var registered = await RegisterClientAsync(client, discovery, SignInClientMetadata("sign-in-limited"));
        var configurationUri = new Uri(
            registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>(),
            UriKind.RelativeOrAbsolute);

        var within = SignInClientMetadata("sign-in-limited");
        within[RequestMembers.ClientId] = registered[ResponseMembers.ClientId]!.GetValue<string>();
        var servedWithin = await client.SendAsync(
            Update(configurationUri, registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>(), within),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, servedWithin.StatusCode);

        var widened = SignInClientMetadata("sign-in-limited");
        widened[RequestMembers.ClientId] = registered[ResponseMembers.ClientId]!.GetValue<string>();
        widened[RequestMembers.GrantTypes]!.AsArray().Add(GrantTypes.ClientCredentials);
        var accessToken = JsonNode.Parse(await servedWithin.Content.ReadAsStringAsync(
                TestContext.Current.CancellationToken))?[ResponseMembers.RegistrationAccessToken]?.GetValue<string>()
            ?? registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>();

        var response = await client.SendAsync(
            Update(configurationUri, accessToken, widened),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, await ReadErrorAsync(response));
    }

    private static HttpRequestMessage Update(Uri configurationUri, string accessToken, JsonObject metadata)
    {
        var update = new HttpRequestMessage(HttpMethod.Put, configurationUri) { Content = JsonContent.Create(metadata) };
        update.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        return update;
    }

    private static async Task<string?> ReadErrorAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync())?[ErrorMember]?.GetValue<string>();
}
