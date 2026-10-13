// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The routes the library maps: at the paths <see cref="OidcRouteOptions"/> gives them, under the prefix the host
/// passes, and out of reach of the host's own routes.
/// </summary>
public class LibraryRoutesTests(TestFactory factory) : TestBase(factory)
{
    private const string MovedIntrospectionPath = "/oauth2/introspect";
    private const string RoutePrefix = "/oauth";

    [Fact]
    public async Task AConfiguredPathMovesTheEndpointAndItsUrl()
    {
        var original = (await FetchDiscoveryAsync(CreateClient())).IntrospectionEndpoint;
        Assert.NotNull(original);

        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.Configure<OidcRouteOptions>(routes => routes.Introspection = MovedIntrospectionPath)));
        using var client = host.CreateClient(ClientOptions);

        var moved = (await FetchDiscoveryAsync(client)).IntrospectionEndpoint;
        Assert.Equal(MovedIntrospectionPath, moved?.AbsolutePath);

        using var atOriginal = await PostIntrospectionAsync(client, original.AbsolutePath);
        Assert.Equal(HttpStatusCode.NotFound, atOriginal.StatusCode);

        using var atMoved = await PostIntrospectionAsync(client, MovedIntrospectionPath);
        Assert.NotEqual(HttpStatusCode.NotFound, atMoved.StatusCode);
    }

    [Fact]
    public async Task APrefixMountsTheEndpointsAndTheirUrls()
    {
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.UseSetting(TestConstants.RoutePrefixConfigKey, RoutePrefix));
        using var client = host.CreateClient(ClientOptions);

        using var bare = await client.GetAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, bare.StatusCode);

        using var prefixed = await client.GetAsync(
            RoutePrefix + "/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        var document = JsonNode.Parse(await prefixed.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(HttpStatusCode.OK, prefixed.StatusCode);
        Assert.Equal(
            RoutePrefix + "/connect/token",
            new Uri(document[ConfigurationResponse.Parameters.TokenEndpoint]!.GetValue<string>()).AbsolutePath);
    }

    /// <summary>
    /// A client authenticating with HTTP Basic gets its token, so the token endpoint reads the Authorization header.
    /// </summary>
    [Fact]
    public async Task ATokenRequestAuthenticatedWithBasicIsServed()
    {
        using var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(
                new Dictionary<string, string> { [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Basic,
            Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{TestConstants.ClientSecretBasicClientId}:{TestConstants.ConfidentialClientSecret}")));

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode == HttpStatusCode.OK, body);
        Assert.NotNull(JsonNode.Parse(body)![ResponseParameters.AccessToken]);
    }

#if !MINIMAL_API_TRANSPORT
    /// <summary>
    /// The host's own <c>{controller}/{action}</c> route reaches none of the library's actions: the test host maps
    /// one beside the library's routes.
    /// </summary>
    [Theory]
    [InlineData("GET", "/Discovery/ConfigurationAsync")]
    [InlineData("GET", "/Discovery/Configuration")]
    [InlineData("POST", "/Token/TokenAsync")]
    [InlineData("POST", "/Token/IntrospectionAsync")]
    public async Task TheHostsConventionalRouteReachesNoLibraryAction(string method, string path)
    {
        using var client = CreateClient();
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
#endif

    private static Task<HttpResponseMessage> PostIntrospectionAsync(HttpClient client, string path)
        => client.PostAsync(
            path,
            new FormUrlEncodedContent(new Dictionary<string, string> { [IntrospectionRequest.Parameters.Token] = "any" }),
            TestContext.Current.CancellationToken);

    private static readonly WebApplicationFactoryClientOptions ClientOptions = new()
    {
        AllowAutoRedirect = false,
        BaseAddress = TestServerAddress.BaseAddress,
    };
}
