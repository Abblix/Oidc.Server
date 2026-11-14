// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>
/// A route template's tokens are replaced by the section's values or by their fallbacks, in the forms version 2.4
/// accepted.
/// </summary>
public class RouteTemplateResolverTests
{
    private static RouteTemplateResolver Resolver(params (string Key, string Value)[] entries)
        => new(ConfigurableRoutesExtensions.DefaultPrefix, new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(entry =>
                new KeyValuePair<string, string?>($"Routes:{entry.Key}", entry.Value)))
            .Build()
            .GetSection("Routes"));

    /// <summary>
    /// A doubled bracket in a fallback is MVC's escaped literal, so it stays in the fallback for MVC to read.
    /// </summary>
    [Theory]
    [InlineData("[route:a?a]]b]/x", "a]]b/x")]
    [InlineData("[route:a?a[[b]/x", "a[[b/x")]
    public void AnEscapedBracketStaysInTheFallback(string template, string expected)
        => Assert.Equal(expected, Resolver().Resolve(template).Template);

    [Fact]
    public void ATokenInsideAFallbackClosesBeforeTheTokenHoldingIt()
        => Assert.Equal("x/y", Resolver().Resolve("[route:a?[route:b?x]]/y").Template);

    /// <summary>A fallback whose brackets do not pair is no fallback, so the token is not read at all.</summary>
    [Fact]
    public void AFallbackWithAnUnclosedBracketLeavesTheTemplateAsItIs()
        => Assert.Equal("[route:a?[x]", Resolver().Resolve("[route:a?[x]").Template);

    [Fact]
    public void AnEmptyFallbackResolvesToNothing()
        => Assert.Equal("/y", Resolver().Resolve("[route:x?]/y").Template);

    [Theory]
    [InlineData(false, "v1/x/v1")]
    [InlineData(true, "v2/x/v2")]
    public void ATokenWrittenTwiceIsResolvedBothTimes(bool configured, string expected)
    {
        var resolver = configured ? Resolver(("ApiPrefix", "v2")) : Resolver();

        var (template, fromSection) = resolver.Resolve("[route:ApiPrefix?v1]/x/[route:ApiPrefix?v1]");

        Assert.Equal(expected, template);
        Assert.Equal(configured, fromSection);
    }

    [Fact]
    public void ATokenReachedThroughItsOwnValueIsRefused()
        => Assert.Throws<InvalidOperationException>(() =>
            Resolver(("a", "[route:b]"), ("b", "[route:a]/x")).Resolve("[route:a]"));
}
