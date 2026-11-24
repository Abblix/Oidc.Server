// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A client exchanging tokens addressed to it as a resource server exchanges another client's access token issued for
/// its location, and no access token whose request named no resource.
/// </summary>
public class CrossClientTokenExchangeTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// An access token another client obtained for the resource server's location is exchanged by the resource server.
    /// </summary>
    [Fact]
    public async Task AnAccessTokenForTheClientsLocation_IsExchanged()
    {
        await using var host = ResourceServerHost(TestConstants.ApiResource);
        var client = CreateClientOf(host);
        var discovery = await FetchDiscoveryAsync(client);
        var tokens = await ObtainResourceGrantTokensAsync(client, discovery);

        var status = await ExchangeAsync(client, discovery, tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>());

        Assert.Equal(HttpStatusCode.OK, status);
    }

    /// <summary>
    /// An access token another client obtained naming no resource is addressed to this server, not to the resource
    /// server, and is not exchanged by it.
    /// </summary>
    [Fact]
    public async Task AnAccessTokenNamingNoResource_IsNotExchanged()
    {
        await using var host = ResourceServerHost(TestConstants.ApiResource);
        var client = CreateClientOf(host);
        var discovery = await FetchDiscoveryAsync(client);
        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);

        var status = await ExchangeAsync(client, discovery, tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>());

        Assert.Equal(HttpStatusCode.BadRequest, status);
    }

    /// <summary>
    /// A client naming the issuer as its location would be the resource server of every access token whose request
    /// named no resource, so a host declaring one does not start, and the client exchanges no such token.
    /// </summary>
    [Fact]
    public async Task AHostWhoseClientNamesTheIssuerAsItsLocation_DoesNotStart()
    {
        var issuer = (await FetchDiscoveryAsync(CreateClient())).Issuer.OriginalString;
        await using var host = ResourceServerHost(issuer);

        Assert.Throws<OptionsValidationException>(() => CreateClientOf(host));
    }

    private WebApplicationFactory<Program> ResourceServerHost(string location)
        => Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.PostConfigure<TestTenantSettings>(tenant =>
                tenant.Clients =
                [
                    .. tenant.Clients.Select(client => client.ClientId == TestConstants.UnrestrictedClientId
                        ? client with
                        {
                            CrossClientSubjectTokenExchange = CrossClientSubjectTokenExchange.AddressedToClient,
                            ResourceLocations = [new Uri(location)],
                        }
                        : client),
                ])));

    private static HttpClient CreateClientOf(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    private static async Task<HttpStatusCode> ExchangeAsync(HttpClient client, DiscoveryDocument discovery, string token)
    {
        var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.TokenExchange,
            [TokenRequest.Parameters.SubjectToken] = token,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.AccessToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.UnrestrictedClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });
        return response.StatusCode;
    }
}
