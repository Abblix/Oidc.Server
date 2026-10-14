// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>
/// A configuration section written for version 2.4 sets the endpoint paths it names, in the form 2.4 read them.
/// </summary>
public class ConfigureRoutesTests
{
    private const string Section = "Routes";

    private static OidcRouteOptions Routes(params (string Key, string Value)[] entries)
        => Routes(ConfigurableRoutesExtensions.DefaultPrefix, null, entries);

    private static OidcRouteOptions Routes(
        string prefix,
        Action<IServiceCollection>? before,
        params (string Key, string Value)[] entries)
    {
        var section = new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(entry =>
                new KeyValuePair<string, string?>($"{Section}:{entry.Key}", entry.Value)))
            .Build()
            .GetSection(Section);

        var services = new ServiceCollection();
        before?.Invoke(services);
        services.ConfigureRoutes(section, prefix);
        return services.BuildServiceProvider().GetRequiredService<IOptions<OidcRouteOptions>>().Value;
    }

    [Fact]
    public void AnEmptySectionLeavesEveryPathAsItWas()
        => Assert.Equivalent(new OidcRouteOptions(), Routes());

    [Fact]
    public void TheBaseMovesEveryConnectEndpointAndNoWellKnownOne()
    {
        var routes = Routes(("base", "~/oauth2"));

        Assert.Equal("/oauth2/authorize", routes.Authorize);
        Assert.Equal("/oauth2/token", routes.Token);
        Assert.Equal("/oauth2/introspect", routes.Introspection);
        Assert.Equal("/oauth2/register", routes.Register);
        Assert.Equal("/oauth2/register/{clientId}", routes.RegisterClient);
        Assert.Equal(new OidcRouteOptions().Configuration, routes.Configuration);
        Assert.Equal(new OidcRouteOptions().Keys, routes.Keys);
    }

    [Fact]
    public void TheWellKnownBaseMovesTheDiscoveryEndpoints()
    {
        var routes = Routes(("well_known", "~/meta"));

        Assert.Equal("/meta/openid-configuration", routes.Configuration);
        Assert.Equal("/meta/oauth-authorization-server", routes.OAuthAuthorizationServer);
        Assert.Equal("/meta/jwks", routes.Keys);
        Assert.Equal(new OidcRouteOptions().Token, routes.Token);
    }

    /// <summary>Every version 2.4 key names the endpoint it named then.</summary>
    [Theory]
    [InlineData("authorize", nameof(OidcRouteOptions.Authorize))]
    [InlineData("par", nameof(OidcRouteOptions.PushedAuthorizationRequest))]
    [InlineData("userinfo", nameof(OidcRouteOptions.UserInfo))]
    [InlineData("endsession", nameof(OidcRouteOptions.EndSession))]
    [InlineData("checksession", nameof(OidcRouteOptions.CheckSession))]
    [InlineData("token", nameof(OidcRouteOptions.Token))]
    [InlineData("revoke", nameof(OidcRouteOptions.Revocation))]
    [InlineData("introspect", nameof(OidcRouteOptions.Introspection))]
    [InlineData("bc_authorize", nameof(OidcRouteOptions.BackChannelAuthentication))]
    [InlineData("deviceauthorization", nameof(OidcRouteOptions.DeviceAuthorization))]
    [InlineData("register", nameof(OidcRouteOptions.Register))]
    [InlineData("configuration", nameof(OidcRouteOptions.Configuration))]
    [InlineData("oauth_authorization_server", nameof(OidcRouteOptions.OAuthAuthorizationServer))]
    [InlineData("jwks", nameof(OidcRouteOptions.Keys))]
    public void AKeyOfVersion24SetsItsEndpoint(string key, string property)
    {
        var routes = Routes((key, "~/moved"));

        Assert.Equal("/moved", typeof(OidcRouteOptions).GetProperty(property)!.GetValue(routes));
    }

    [Fact]
    public void AValueBuiltFromAnotherTokenResolvesThroughIt()
    {
        var routes = Routes(("base", "~/oauth2"), ("token", "[route:base]/issue"));

        Assert.Equal("/oauth2/issue", routes.Token);
    }

    [Fact]
    public void AnotherPrefixReadsTokensOpenedByIt()
    {
        var routes = Routes("path", null, ("base", "~/oauth2"), ("token", "[path:base]/issue"));

        Assert.Equal("/oauth2/issue", routes.Token);
    }

    [Fact]
    public void APathSetInCodeStandsWhereTheSectionIsSilent()
    {
        var routes = Routes(
            ConfigurableRoutesExtensions.DefaultPrefix,
            services => services.Configure<OidcRouteOptions>(options => options.Token = "/in-code/token"),
            ("introspect", "~/moved/introspect"));

        Assert.Equal("/in-code/token", routes.Token);
        Assert.Equal("/moved/introspect", routes.Introspection);
    }

    [Fact]
    public void ATokenReferringBackToItselfStopsTheOptions()
        => Assert.Throws<InvalidOperationException>(() =>
            Routes(("base", "[route:token]"), ("token", "[route:base]/token")));
}
