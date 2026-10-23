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
using Microsoft.Extensions.DependencyInjection;
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
        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.PostConfigure<TestTenantSettings>(tenant => tenant.MtlsBaseUri = mtlsBaseUri)));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

        var discovery = JsonNode.Parse(
            await client.GetStringAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken))!;
        var ordinary = new Uri(discovery[endpoint]!.GetValue<string>());
        var alias = new Uri(
            discovery[ConfigurationResponse.Parameters.MtlsEndpointAliases]![endpoint]!.GetValue<string>());

        Assert.Equal(mtlsBaseUri.GetLeftPart(UriPartial.Authority), alias.GetLeftPart(UriPartial.Authority));
        Assert.Equal(ordinary.AbsolutePath, alias.AbsolutePath);
    }
}
