// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Infrastructure;
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

    private static IConfigurationSection SectionOf(params (string Key, string Value)[] entries)
        => new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(entry =>
                new KeyValuePair<string, string?>($"{Section}:{entry.Key}", entry.Value)))
            .Build()
            .GetSection(Section);

    private static OidcRouteOptions Routes(params (string Key, string Value)[] entries)
        => Routes(ConfigurableRoutesExtensions.DefaultPrefix, null, entries);

    private static OidcRouteOptions Routes(
        string prefix,
        Action<IServiceCollection>? before,
        params (string Key, string Value)[] entries)
    {
        var services = new ServiceCollection();
        before?.Invoke(services);
        services.ConfigureRoutes(SectionOf(entries), prefix);
        return services.BuildServiceProvider().GetRequiredService<IOptions<OidcRouteOptions>>().Value;
    }

    [Fact]
    public void AnEmptySectionLeavesEveryPathSetInCode()
    {
        var inCode = typeof(OidcRouteOptions).GetProperties().Where(property => property.CanWrite).ToList();

        var routes = Routes(
            ConfigurableRoutesExtensions.DefaultPrefix,
            services => services.Configure<OidcRouteOptions>(options =>
            {
                foreach (var property in inCode)
                    property.SetValue(options, "/in-code/" + property.Name);
            }));

        Assert.All(inCode, property => Assert.Equal("/in-code/" + property.Name, property.GetValue(routes)));
    }

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

    [Theory]
    [InlineData("[Route:base]/issue")]
    [InlineData("~token")]
    public void APathThatCannotBeARouteStopsTheOptions(string value)
        => Assert.Throws<InvalidOperationException>(() => Routes(("token", value)));

    [Fact]
    public void ATildeAloneIsTheApplicationRoot()
        => Assert.Equal("/", Routes(("token", "~")).Token);

    [Fact]
    public void ALaterCallReplacesAnEarlierOne()
    {
        var services = new ServiceCollection();
        services.ConfigureRoutes(SectionOf(("token", "~/first/token")));
        services.ConfigureRoutes(SectionOf(("introspect", "~/second/introspect")));
        var routes = services.BuildServiceProvider().GetRequiredService<IOptions<OidcRouteOptions>>().Value;

        Assert.Equal(new OidcRouteOptions().Token, routes.Token);
        Assert.Equal("/second/introspect", routes.Introspection);
    }

    [Fact]
    public void ATokenInAHostRouteIsResolvedAndARouteWithoutOneIsLeftAsItIs()
    {
        var actions = HostActions(SectionOf(("ApiPrefix", "v2")));

        Assert.Equal("v2/users", RouteOf<HostTokenizedController>(actions));
        Assert.Equal("plain/HostPlain/items", RouteOf<HostPlainController>(actions));
    }

    /// <summary>The form version 2.4 resolved: a token in an action's route, under a route of the controller.</summary>
    [Theory]
    [InlineData(null, "api/items/{id}")]
    [InlineData("things", "api/things/{id}")]
    public void ATokenInAnActionRouteIsResolved(string? item, string expected)
    {
        var actions = HostActions(item is null ? SectionOf() : SectionOf(("Item", item)));

        Assert.Equal(expected, RouteOf<HostActionTokenController>(actions));
    }

    /// <summary>A fallback ends at its own closing bracket, so what follows the token stays in the route.</summary>
    [Theory]
    [InlineData(null, "v1/HostBracket")]
    [InlineData("v2", "v2/HostBracket")]
    public void WhatFollowsATokenStaysInTheRoute(string? prefix, string expected)
    {
        var actions = HostActions(prefix is null ? SectionOf() : SectionOf(("ApiPrefix", prefix)));

        Assert.Equal(expected, RouteOf<HostBracketController>(actions));
    }

    [Theory]
    [InlineData(false, "a/b")]
    [InlineData(true, "aa/bb")]
    public void TwoTokensInOneRouteAreBothResolved(bool configured, string expected)
    {
        var actions = HostActions(configured ? SectionOf(("First", "aa"), ("Second", "bb")) : SectionOf());

        Assert.Equal(expected, RouteOf<HostTwoTokensController>(actions));
    }

    [Fact]
    public void ALaterCallResolvesTheHostsRoutesFromItsSection()
    {
        var actions = HostActions(SectionOf(("ApiPrefix", "v2")), SectionOf(("ApiPrefix", "v3")));

        Assert.Equal("v3/users", RouteOf<HostTokenizedController>(actions));
    }

    private static readonly Type[] HostControllers =
    [
        typeof(HostTokenizedController),
        typeof(HostPlainController),
        typeof(HostActionTokenController),
        typeof(HostBracketController),
        typeof(HostTwoTokensController),
    ];

    /// <summary>The host's actions as MVC built them, after one call of ConfigureRoutes per section, in order.</summary>
    private static List<ControllerActionDescriptor> HostActions(params IConfigurationSection[] sections)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddControllers()
            .ConfigureApplicationPartManager(parts => parts.FeatureProviders.Add(new OnlyHostControllers()))
            .AddApplicationPart(typeof(HostTokenizedController).Assembly);
        foreach (var section in sections)
            services.ConfigureRoutes(section);

        return services.BuildServiceProvider()
            .GetRequiredService<IActionDescriptorCollectionProvider>().ActionDescriptors.Items
            .OfType<ControllerActionDescriptor>()
            .ToList();
    }

    private static string? RouteOf<TController>(IEnumerable<ControllerActionDescriptor> actions)
        => Assert.Single(actions, action => action.ControllerTypeInfo == typeof(TController)).AttributeRouteInfo?.Template;

    /// <summary>Keeps the host controllers of this assembly and no other type that might look like one.</summary>
    private sealed class OnlyHostControllers : IApplicationFeatureProvider<ControllerFeature>
    {
        public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature)
        {
            var other = feature.Controllers.Where(controller => !HostControllers.Contains(controller.AsType())).ToList();
            foreach (var controller in other)
                feature.Controllers.Remove(controller);
        }
    }

    [Fact]
    public void ATokenReferringBackToItselfStopsTheOptions()
        => Assert.Throws<InvalidOperationException>(() =>
            Routes(("base", "[route:token]"), ("token", "[route:base]/token")));
}
