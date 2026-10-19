// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>
/// A host asks for a path that is not a controller route, such as a fallback under a configurable path or a page
/// address it publishes, and gets it resolved from the section its route tokens are read from.
/// </summary>
public class RouteTemplateResolverServiceTests
{
    private const string Section = "Routes";

    private static IConfigurationSection SectionOf(params (string Key, string Value)[] entries)
        => new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(entry =>
                new KeyValuePair<string, string?>($"{Section}:{entry.Key}", entry.Value)))
            .Build()
            .GetSection(Section);

    private static IRouteTemplateResolver ResolverOf(
        string prefix = ConfigurableRoutesExtensions.DefaultPrefix,
        params (string Key, string Value)[] entries)
    {
        var services = new ServiceCollection();
        services.ConfigureRoutes(SectionOf(entries), prefix);
        return services.BuildServiceProvider().GetRequiredService<IRouteTemplateResolver>();
    }

    [Theory]
    [InlineData("[route:api?~/api]", "/manage/api")]
    [InlineData("[route:passkeys_enroll?~/manage/passkeys]", "/manage/passkeys")]
    [InlineData("[route:api?~/api]/{**rest}", "/manage/api/{**rest}")]
    public void ATokenTheSectionNames_ResolvesToItsValue(string template, string expected)
        => Assert.Equal(expected, ResolverOf(ConfigurableRoutesExtensions.DefaultPrefix, ("api", "~/manage/api")).Resolve(template));

    [Fact]
    public void ATokenTheSectionIsSilentOn_ResolvesToItsFallback()
        => Assert.Equal("/manage/passkeys", ResolverOf().Resolve("[route:passkeys_enroll?~/manage/passkeys]"));

    [Fact]
    public void AValueBuiltFromAnotherToken_IsResolvedThrough()
        => Assert.Equal(
            "/manage/api",
            ResolverOf(ConfigurableRoutesExtensions.DefaultPrefix, ("base", "~/manage"), ("api", "[route:base]/api")).Resolve("[route:api?~/api]"));

    [Theory]
    [InlineData("/plain/path", "/plain/path")]
    [InlineData("~/plain/path", "/plain/path")]
    [InlineData("~", "/")]
    public void ATemplateWithNoToken_ComesBackAsAPath(string template, string expected)
        => Assert.Equal(expected, ResolverOf().Resolve(template));

    [Fact]
    public void TheTokenPrefixGivenToConfigureRoutes_IsTheOneResolved()
    {
        var resolver = ResolverOf("path", ("api", "~/manage/api"));

        Assert.Equal("/manage/api", resolver.Resolve("[path:api?~/api]"));
        Assert.Equal("[route:api?~/api]", resolver.Resolve("[route:api?~/api]"));
    }

    [Fact]
    public void ATokenWithNeitherAValueNorAFallback_IsRefused()
        => Assert.Throws<InvalidOperationException>(() => ResolverOf().Resolve("[route:api]"));

    [Fact]
    public void ATildeNotFollowedByASlash_IsRefused()
        => Assert.Throws<InvalidOperationException>(() => ResolverOf(ConfigurableRoutesExtensions.DefaultPrefix, ("api", "~api")).Resolve("[route:api]"));

    [Fact]
    public void ALaterCallOfConfigureRoutes_ReplacesTheResolver()
    {
        var services = new ServiceCollection();
        services.ConfigureRoutes(SectionOf(("api", "~/first")));
        services.ConfigureRoutes(SectionOf(("api", "~/second")));

        var resolver = services.BuildServiceProvider().GetRequiredService<IRouteTemplateResolver>();

        Assert.Equal("/second", resolver.Resolve("[route:api]"));
    }

    [Fact]
    public void AResolverOfTheHostsOwn_Wins()
    {
        var own = new OwnResolver();
        var services = new ServiceCollection();
        services.AddSingleton<IRouteTemplateResolver>(own);
        services.ConfigureRoutes(SectionOf(("api", "~/manage/api")));

        Assert.Same(own, services.BuildServiceProvider().GetRequiredService<IRouteTemplateResolver>());
    }

    private sealed class OwnResolver : IRouteTemplateResolver
    {
        public string Resolve(string template) => template;
    }
}
