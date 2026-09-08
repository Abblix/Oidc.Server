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
    /// The route carrying a colon composes intact. It is the one shape here that a URI parser can read as
    /// something else - a scheme - and the specification names two routes that way.
    /// </summary>
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

    private static SharedSignalsTransmitterOptions BareOptions() => new() { Issuer = Issuer };
}
