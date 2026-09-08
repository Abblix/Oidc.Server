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
/// the shape composed from a host's own base.
/// </summary>
public sealed class ManagementEndpointLocatorTests
{
    private const string Issuer = "https://tr.example.com";
    private const string Route = "/stream";

    /// <summary>
    /// A transmitter that neither maps the routes nor names a base serves no Stream Management API, and
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
    /// A host that names a base has the API served somewhere this deployment does not map, so the
    /// document names it whether or not anything was mapped here.
    /// </summary>
    [Fact]
    public void WithAHostsOwnBaseAndNoMapping_TheAddressIsStillNamed()
    {
        var locator = new ManagementEndpointLocator(BareOptions() with
        {
            ManagementApiBase = new Uri("https://gateway.example/"),
        });

        Assert.Equal(new Uri("https://gateway.example/stream"), locator.Of(Route));
    }

    /// <summary>
    /// The host's base wins over the mapped address, as the poll endpoint's does: a deployment that maps
    /// the routes internally and is reached through a gateway must advertise the gateway.
    /// </summary>
    [Fact]
    public void WithBothSources_TheHostsBaseWins()
    {
        var locator = new ManagementEndpointLocator(BareOptions() with
        {
            ManagementApiBase = new Uri("https://gateway.example/"),
        });
        locator.ServedAt(route => new Uri($"{Issuer}/ssf{route}"));

        Assert.Equal(new Uri("https://gateway.example/stream"), locator.Of(Route));
    }

    /// <summary>
    /// A base with a path of its own keeps it. This is the case the option exists for and the one that
    /// composition gets wrong by default.
    /// </summary>
    /// <remarks>
    /// Every route here is rooted, and resolving a rooted reference against a base REPLACES the whole
    /// path - with or without a trailing slash on the base. So a gateway at <c>/ssf</c> would be
    /// advertised at the root, which is a 404 in a document receivers cache: the failure this type was
    /// written to end, arriving through the option written to avoid it. Both spellings are driven
    /// because a host will write either and neither is wrong.
    /// </remarks>
    [Theory]
    [InlineData("https://gateway.example/ssf")]
    [InlineData("https://gateway.example/ssf/")]
    public void ABaseWithAPathOfItsOwn_KeepsIt(string @base)
    {
        var locator = new ManagementEndpointLocator(BareOptions() with
        {
            ManagementApiBase = new Uri(@base),
        });

        Assert.Equal(new Uri("https://gateway.example/ssf/stream"), locator.Of(Route));
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
    public void ARouteCarryingAColon_SurvivesComposition()
    {
        var locator = new ManagementEndpointLocator(BareOptions() with
        {
            ManagementApiBase = new Uri("https://gateway.example/ssf"),
        });

        Assert.Equal(
            new Uri("https://gateway.example/ssf/subjects:add"),
            locator.Of("/subjects:add"));
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
    /// A route written without a leading separator composes the same way.
    /// </summary>
    /// <remarks>
    /// The five routes this package advertises are all rooted, so this shape does not arise from the
    /// mapping - but the method is public, and the two spellings fail in opposite directions under any
    /// composition that cares: a rooted route resolved against a base discards its path, a relative one
    /// concatenated to a path with no separator welds two segments into one.
    /// </remarks>
    [Fact]
    public void ARouteWithNoLeadingSeparator_ComposesTheSame()
    {
        var locator = new ManagementEndpointLocator(BareOptions() with
        {
            ManagementApiBase = new Uri("https://gateway.example/ssf"),
        });

        Assert.Equal(new Uri("https://gateway.example/ssf/stream"), locator.Of("stream"));
    }

    /// <summary>
    /// A base whose path begins with two separators keeps its host.
    /// </summary>
    /// <remarks>
    /// This is what a host gets by joining a base already ending in a separator to <c>/ssf</c>, so it is a
    /// spelling that arrives by accident rather than by intent. Composed as a reference it becomes a
    /// network-path reference and replaces the AUTHORITY - <c>https://ssf/stream</c> - which sends the
    /// document's addresses to a host nobody named. The path stays odd; the host does not move.
    /// </remarks>
    [Fact]
    public void ABaseWithADoubledSeparator_KeepsItsHost()
    {
        var locator = new ManagementEndpointLocator(BareOptions() with
        {
            ManagementApiBase = new Uri("https://gateway.example//ssf"),
        });

        Assert.Equal("gateway.example", locator.Of(Route)!.Host);
    }

    private static SharedSignalsTransmitterOptions BareOptions() => new() { Issuer = Issuer };
}
