// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// What a host gets from <c>IOidcEndpointResolver</c> on the MVC transport - the same contract the Minimal API
/// adapter answers, so code needing an OIDC endpoint's URL is written once and survives a change of adapter.
/// </summary>
/// <remarks>
/// The twin of the Minimal API suite's file of the same name, deliberately asserting the same things against
/// the same probe path. A contract claimed by two adapters and exercised on one is a contract with an untested
/// half: the promise it makes is precisely that both halves agree.
/// </remarks>
public class OidcEndpointResolverTests(TestFactory factory) : TestBase(factory), IClassFixture<TestFactory>
{
    private static async Task<string> ResolveAsync(HttpClient client, OidcEndpoints endpoint)
        => await client.GetStringAsync(
            $"{TestConstants.EndpointResolverProbePath}/{endpoint}",
            TestContext.Current.CancellationToken);

    /// <summary>
    /// Every endpoint the discovery document advertises resolves to the same URL through the contract. Driving
    /// the whole set rather than one endpoint is what catches a mis-keyed entry in the endpoint-to-template
    /// table, which would otherwise surface as the adapter quietly handing out another endpoint's address.
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
        var client = CreateClient();

        var raw = await client.GetStringAsync(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        var advertised = JsonNode.Parse(raw)!.AsObject()[discoveryParameter]?.GetValue<string>();
        Assert.False(string.IsNullOrEmpty(advertised), $"discovery advertises no {discoveryParameter}");

        Assert.Equal(advertised, await ResolveAsync(client, endpoint));
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
        => Assert.Equal(string.Empty, await ResolveAsync(CreateClient(), endpoints));
}
