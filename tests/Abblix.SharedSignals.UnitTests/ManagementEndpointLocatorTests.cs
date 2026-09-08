// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Which of the two sources of a management address wins, what a transmitter with neither answers, and
/// what the offered composition produces for a host that uses it.
/// </summary>
public sealed class ManagementEndpointLocatorTests
{
    private const string Issuer = "https://tr.example.com";
    private const string Route = "/stream";

    /// <summary>
    /// A transmitter that neither maps the routes nor names a source serves no Stream Management API, and
    /// the configuration document leaves the five members out rather than naming addresses nothing
    /// answers.
    /// </summary>
    [Fact]
    public void WithNeitherSource_ThereIsNoAddress()
    {
        var locator = new ManagementEndpointLocator(BareOptions());

        Assert.Null(locator.Of(Route));
    }

    [Fact]
    public void WithMappedRoutes_TheMappedAddressIsUsed()
    {
        var locator = new ManagementEndpointLocator(BareOptions());
        locator.ServedAt(route => new Uri($"{Issuer}/ssf{route}"));

        Assert.Equal(new Uri($"{Issuer}/ssf/stream"), locator.Of(Route));
    }

    /// <summary>
    /// A host that names a source has the API served somewhere this deployment does not map, so the
    /// document names it whether or not anything was mapped here.
    /// </summary>
    [Fact]
    public void WithAHostsOwnSourceAndNoMapping_TheAddressIsStillNamed()
    {
        var locator = new ManagementEndpointLocator(BareOptions() with
        {
            ManagementEndpointFactory = route => new Uri($"https://gateway.example{route}"),
        });

        Assert.Equal(new Uri("https://gateway.example/stream"), locator.Of(Route));
    }

    /// <summary>
    /// The host's source wins over the mapped address, as the poll endpoint's does: a deployment that
    /// maps the routes internally and is reached through a gateway must advertise the gateway.
    /// </summary>
    [Fact]
    public void WithBothSources_TheHostsSourceWins()
    {
        var locator = new ManagementEndpointLocator(BareOptions() with
        {
            ManagementEndpointFactory = route => new Uri($"https://gateway.example{route}"),
        });
        locator.ServedAt(route => new Uri($"{Issuer}/ssf{route}"));

        Assert.Equal(new Uri("https://gateway.example/stream"), locator.Of(Route));
    }

    /// <summary>
    /// A second mapping is refused rather than replacing the first: a document served in between would
    /// name the first, so which addresses a receiver cached would depend on when each call ran.
    /// </summary>
    [Fact]
    public void ASecondMapping_IsRefused()
    {
        var locator = new ManagementEndpointLocator(BareOptions());
        locator.ServedAt(route => new Uri($"{Issuer}/ssf{route}"));

        Assert.Throws<InvalidOperationException>(
            () => locator.ServedAt(route => new Uri($"{Issuer}/other{route}")));
    }

    /// <summary>
    /// The offered composition keeps the base's own path, in both spellings, and for both spellings of
    /// the route.
    /// </summary>
    /// <remarks>
    /// Every route the document advertises is rooted, and resolving a rooted reference against a base
    /// REPLACES the base's path; a relative one drops the base's last segment unless the base ends in a
    /// separator. So three of the four spellings would advertise a gateway at the root. This is the trap
    /// the helper exists to spare a host, which is why its rows live here rather than in the host.
    /// </remarks>
    [Theory]
    [InlineData("https://gateway.example/ssf", "/stream")]
    [InlineData("https://gateway.example/ssf/", "/stream")]
    [InlineData("https://gateway.example/ssf", "stream")]
    [InlineData("https://gateway.example/ssf/", "stream")]
    public void UnderABase_KeepsThePathInEverySpelling(string @base, string route)
    {
        var of = ManagementEndpointLocator.Under(new Uri(@base));

        Assert.Equal(new Uri("https://gateway.example/ssf/stream"), of(route));
    }

    /// <summary>
    /// A base whose path begins with two separators keeps its host.
    /// </summary>
    /// <remarks>
    /// This is what a host gets by joining a base already ending in a separator to <c>/ssf</c>, so it is
    /// a spelling that arrives by accident rather than by intent. Composed as a reference it becomes a
    /// network-path reference and replaces the AUTHORITY - <c>https://ssf/stream</c> - sending the
    /// document's addresses to a host nobody named. The path stays odd; the host does not move.
    /// </remarks>
    [Fact]
    public void UnderABaseWithADoubledSeparator_KeepsItsHost()
    {
        var of = ManagementEndpointLocator.Under(new Uri("https://gateway.example//ssf"));

        Assert.Equal("gateway.example", of(Route).Host);
    }

    /// <summary>
    /// The published TEXT of the address, which is what a receiver reads and caches.
    /// </summary>
    /// <remarks>
    /// Asserted as a string because every other row here compares <c>Uri</c> objects, and <c>Uri</c>
    /// equality ignores a default port: <c>https://gw.example/x</c> and <c>https://gw.example:443/x</c>
    /// are equal, while the document publishes the second verbatim. A composition that keeps the port it
    /// was handed - which is what a builder does - is invisible to the whole file without this row.
    /// </remarks>
    [Theory]
    [InlineData("https://gateway.example/ssf", "https://gateway.example/ssf/stream")]
    [InlineData("https://gateway.example:8443/ssf", "https://gateway.example:8443/ssf/stream")]
    public void UnderABase_ThePublishedTextCarriesNoPortTheHostDidNotWrite(string @base, string expected)
    {
        var of = ManagementEndpointLocator.Under(new Uri(@base));

        Assert.Equal(expected, of(Route).OriginalString);
    }

    /// <summary>
    /// The route carrying a colon composes intact, and the specification names two routes that way.
    /// </summary>
    /// <remarks>
    /// Not because a parser would read it as a scheme - it cannot, on a path built from parts. The row is
    /// here because a colon is what any future composition would mangle first, whether by escaping the
    /// segment or by going back to reference resolution, where a bare <c>subjects:add</c> IS read as a
    /// scheme. It is the canary for that change, not a guard against today's code.
    /// </remarks>
    [Fact]
    public void UnderABase_ARouteCarryingAColonSurvives()
    {
        var of = ManagementEndpointLocator.Under(new Uri("https://gateway.example/ssf"));

        Assert.Equal(new Uri("https://gateway.example/ssf/subjects:add"), of("/subjects:add"));
    }

    /// <summary>
    /// A base the composition could not use faithfully is refused where the host writes it.
    /// </summary>
    /// <remarks>
    /// A relative base has no path to append a route to, and a query or fragment cannot survive one being
    /// appended. Refused here rather than dropped, because dropping publishes an address the host did not
    /// write into a document a receiver caches.
    /// </remarks>
    [Theory]
    [InlineData("/ssf", UriKind.Relative)]
    [InlineData("https://gateway.example/ssf?v=1", UriKind.Absolute)]
    [InlineData("https://gateway.example/ssf#top", UriKind.Absolute)]
    public void UnderABaseThatCannotBeUsed_IsRefused(string @base, UriKind kind)
    {
        Assert.Throws<ArgumentException>(() => ManagementEndpointLocator.Under(new Uri(@base, kind)));
    }

    private static SharedSignalsTransmitterOptions BareOptions() => new() { Issuer = Issuer };
}
