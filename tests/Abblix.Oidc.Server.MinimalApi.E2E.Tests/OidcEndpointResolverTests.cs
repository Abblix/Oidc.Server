// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.MinimalApi.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// What a host gets from <c>IOidcEndpointResolver</c>, the contract both transport adapters answer so that code
/// needing an OIDC endpoint's URL is written once and survives a change of adapter.
/// </summary>
/// <remarks>
/// The discovery document is the oracle here rather than a hardcoded path: it is built by a different piece of
/// the adapter, so agreement between the two means the resolver reports where the endpoint really is, not where
/// a second copy of the route table says it should be. That distinction is the whole reason this contract
/// exists - a host that reconstructs the URL from <c>OidcRouteOptions</c> gets it wrong the moment
/// <c>MapOidcEndpoints</c> is given a prefix.
/// </remarks>
public sealed class OidcEndpointResolverTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private const string RoutePrefix = "/oauth";

    private static HttpClient ClientOf(WebApplicationFactory<Program> f) => f.CreateClient(
        new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = TestFactory.BaseAddress });

    private static async Task<string> ResolveAsync(HttpClient client, OidcEndpoints endpoint)
        => await client.GetStringAsync(
            $"{TestConstants.EndpointResolverProbePath}/{endpoint}",
            TestContext.Current.CancellationToken);

    private static async Task<string?> AdvertisedAsync(HttpClient client, string prefix, string parameter)
    {
        var discovery = await client.FetchDiscoveryAsync(prefix);
        return discovery[parameter]?.GetValue<string>();
    }

    /// <summary>
    /// Every endpoint the discovery document advertises resolves to the same URL through the contract. Driving
    /// the whole set rather than one endpoint is what catches a mis-keyed entry in the endpoint-to-name table,
    /// which would otherwise surface as one adapter quietly handing out another endpoint's address.
    /// </summary>
    [Theory]
    [InlineData(OidcEndpoints.Authorize, ConfigurationResponse.Parameters.AuthorizationEndpoint)]
    [InlineData(OidcEndpoints.Token, ConfigurationResponse.Parameters.TokenEndpoint)]
    [InlineData(OidcEndpoints.UserInfo, ConfigurationResponse.Parameters.UserInfoEndpoint)]
    [InlineData(OidcEndpoints.EndSession, ConfigurationResponse.Parameters.EndSessionEndpoint)]
    [InlineData(OidcEndpoints.CheckSession, ConfigurationResponse.Parameters.CheckSessionIframe)]
    [InlineData(OidcEndpoints.Keys, ConfigurationResponse.Parameters.JwksUri)]
    [InlineData(OidcEndpoints.Revocation, ConfigurationResponse.Parameters.RevocationEndpoint)]
    [InlineData(OidcEndpoints.Introspection, ConfigurationResponse.Parameters.IntrospectionEndpoint)]
    [InlineData(OidcEndpoints.RegisterClient, ConfigurationResponse.Parameters.RegistrationEndpoint)]
    [InlineData(OidcEndpoints.PushedAuthorizationRequest, ConfigurationResponse.Parameters.PushedAuthorizationRequestEndpoint)]
    [InlineData(OidcEndpoints.BackChannelAuthentication, ConfigurationResponse.Parameters.BackchannelAuthenticationEndpoint)]
    [InlineData(OidcEndpoints.DeviceAuthorization, ConfigurationResponse.Parameters.DeviceAuthorizationEndpoint)]
    public async Task An_endpoint_resolves_to_the_url_discovery_advertises(
        OidcEndpoints endpoint, string discoveryParameter)
    {
        var client = ClientOf(factory);

        var advertised = await AdvertisedAsync(client, string.Empty, discoveryParameter);
        Assert.False(string.IsNullOrEmpty(advertised), $"discovery advertises no {discoveryParameter}");

        Assert.Equal(advertised, await ResolveAsync(client, endpoint));
    }

    /// <summary>
    /// A route prefix moves the endpoints, and the resolver follows. This is the case a host cannot get right
    /// by reading the configured route out of options: the prefix lives in the MapOidcEndpoints call, not in
    /// the route table.
    /// </summary>
    [Fact]
    public async Task A_route_prefix_is_reflected_in_what_the_resolver_answers()
    {
        await using var prefixed = factory.WithWebHostBuilder(builder =>
            builder.UseSetting(MinimalApiTestConstants.RoutePrefixConfigKey, RoutePrefix));
        var client = ClientOf(prefixed);

        var resolved = await ResolveAsync(client, OidcEndpoints.Authorize);

        Assert.Equal(
            await AdvertisedAsync(client, RoutePrefix, ConfigurationResponse.Parameters.AuthorizationEndpoint),
            resolved);
        Assert.Contains(RoutePrefix, new Uri(resolved).AbsolutePath, StringComparison.Ordinal);
    }

    /// <summary>
    /// A flag combination names a set of endpoints rather than one, so there is no URL to give back. Answering
    /// with some member of the set would be worse than answering nothing: the caller would redirect users at an
    /// endpoint it never asked for.
    /// </summary>
    [Theory]
    [InlineData(OidcEndpoints.All)]
    [InlineData(OidcEndpoints.Base)]
    public async Task A_set_of_endpoints_resolves_to_nothing(OidcEndpoints endpoints)
        => Assert.Equal(string.Empty, await ResolveAsync(ClientOf(factory), endpoints));
}
