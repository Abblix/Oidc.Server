// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A tenant with a mutual TLS host publishes, for each endpoint a client authenticating with its certificate calls,
/// an alias (RFC 8705 section 5) on that host's scheme, host and port, keeping the endpoint's path: an alias on the
/// right host with the wrong path, or on the right path without the port, is a request no endpoint answers.
/// </summary>
public class MtlsEndpointAliasTests(TestFactory factory) : TestBase(factory)
{
    public static TheoryData<string, string> Aliases()
    {
        string[] endpoints =
        [
            ConfigurationResponse.Parameters.TokenEndpoint,
            ConfigurationResponse.Parameters.RevocationEndpoint,
            ConfigurationResponse.Parameters.IntrospectionEndpoint,
            ConfigurationResponse.Parameters.UserInfoEndpoint,
            ConfigurationResponse.Parameters.PushedAuthorizationRequestEndpoint,
            ConfigurationResponse.Parameters.BackchannelAuthenticationEndpoint,
            ConfigurationResponse.Parameters.DeviceAuthorizationEndpoint,
        ];
        string[] mtlsHosts = ["https://mtls.example.com", "https://mtls.example.com:8443"];

        var rows = new TheoryData<string, string>();
        foreach (var endpoint in endpoints)
        {
            foreach (var mtlsHost in mtlsHosts)
                rows.Add(endpoint, mtlsHost);
        }

        return rows;
    }

    [Theory]
    [MemberData(nameof(Aliases))]
    public async Task EachEndpoint_IsAliasedOnTheMutualTlsHost_WithItsPath(string endpoint, string mtlsHost)
    {
        var mtlsBaseUri = new Uri(mtlsHost);
        var discovery = await DiscoveryWithMtlsAsync(mtlsBaseUri);
        var ordinary = new Uri(discovery[endpoint]!.GetValue<string>());
        var alias = new Uri(
            discovery[ConfigurationResponse.Parameters.MtlsEndpointAliases]![endpoint]!.GetValue<string>());

        Assert.Equal(mtlsBaseUri.GetLeftPart(UriPartial.Authority), alias.GetLeftPart(UriPartial.Authority));
        Assert.Equal(ordinary.AbsolutePath, alias.AbsolutePath);
    }

    /// <summary>
    /// With endpoint path discovery switched off the document names no endpoint addresses at all - not the
    /// ordinary ones and not the mutual-TLS aliases. The option exists for deployments that hand their clients
    /// addresses out of band, and publishing them anyway would defeat the only reason to set it; an alias block
    /// with nothing in it is left out, since the block names one or more endpoints (RFC 8705 section 5).
    /// </summary>
    [Fact]
    public async Task WithPathDiscoveryOff_TheDocumentNamesNoEndpointAddresses()
    {
        var discovery = await DiscoveryWithMtlsAsync(
            new Uri("https://mtls.example.com"), options => options.Discovery.AllowEndpointPathsDiscovery = false);

        Assert.Null(discovery[ConfigurationResponse.Parameters.TokenEndpoint]);
        Assert.Null(discovery[ConfigurationResponse.Parameters.UserInfoEndpoint]);
        Assert.Null(discovery[ConfigurationResponse.Parameters.MtlsEndpointAliases]);

        // The issuer stays: it identifies the provider rather than locating an endpoint, and a client that
        // cannot read it cannot validate a token from this server at all.
        Assert.NotNull(discovery[ConfigurationResponse.Parameters.Issuer]);
    }

    /// <summary>
    /// A server serving no token endpoint still publishes the aliases of the endpoints it serves.
    /// </summary>
    [Fact]
    public async Task WithoutATokenEndpoint_TheOtherEndpointsAreStillAliased()
    {
        var discovery = await DiscoveryWithMtlsAsync(
            new Uri("https://mtls.example.com"), options => options.EnabledEndpoints &= ~OidcEndpoints.Token);

        var aliases = Assert.IsType<JsonObject>(discovery[ConfigurationResponse.Parameters.MtlsEndpointAliases]);
        Assert.False(aliases.ContainsKey(ConfigurationResponse.Parameters.TokenEndpoint));
        Assert.True(aliases.ContainsKey(ConfigurationResponse.Parameters.UserInfoEndpoint));
    }

    /// <summary>
    /// The discovery document of a host whose tenant has <paramref name="mtlsBaseUri"/> as its mutual-TLS host.
    /// </summary>
    private async Task<JsonNode> DiscoveryWithMtlsAsync(Uri mtlsBaseUri, Action<OidcOptions>? configure = null)
    {
        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.PostConfigure<TestTenantSettings>(tenant => tenant.MtlsBaseUri = mtlsBaseUri);
            if (configure is not null)
            {
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(Options.DefaultName, configure));
            }
        }));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        return JsonNode.Parse(
            await client.GetStringAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken))!;
    }
}
