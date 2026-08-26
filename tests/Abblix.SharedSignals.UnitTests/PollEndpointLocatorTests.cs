// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SharedSignals.Transmitter;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Which of the two sources of a stream's poll address wins, and what a transmitter with neither answers.
/// </summary>
public sealed class PollEndpointLocatorTests
{
    private const string Issuer = "https://tr.example.com";

    /// <summary>
    /// A transmitter that neither maps the route nor names an address offers no poll delivery. It is the
    /// honest answer rather than a gap: there is nowhere for a receiver to poll, so a create asking for
    /// poll is refused and the configuration document leaves the method out.
    /// </summary>
    [Fact]
    public void WithNeitherSource_NothingIsOffered()
    {
        var locator = new PollEndpointLocator(BareOptions());

        Assert.False(locator.IsOffered);
        Assert.Null(locator.Of("s-1"));
    }

    [Fact]
    public void WithAMappedRoute_TheMappedAddressIsUsed()
    {
        var locator = new PollEndpointLocator(BareOptions());
        locator.ServedAt(streamId => new Uri($"{Issuer}/ssf/poll/{streamId}"));

        Assert.True(locator.IsOffered);
        Assert.Equal(new Uri($"{Issuer}/ssf/poll/s-1"), locator.Of("s-1"));
    }

    /// <summary>
    /// The host's own address wins over the mapped one, which is the whole point of keeping the option: a
    /// deployment behind a gateway is reached at an address that is not where the route sits.
    /// </summary>
    /// <remarks>
    /// The direction matters and only this row states it. Were the mapped address to win, every such
    /// deployment would start handing receivers an internal address the moment it mapped its endpoints -
    /// and nothing else here would notice, because both addresses are well-formed and both are served.
    /// </remarks>
    [Fact]
    public void AHostsOwnAddress_WinsOverTheMappedOne()
    {
        var locator = new PollEndpointLocator(BareOptions() with
        {
            PollEndpointFactory = streamId => new Uri($"https://gateway.example/pull/{streamId}"),
        });
        locator.ServedAt(streamId => new Uri($"{Issuer}/ssf/poll/{streamId}"));

        Assert.Equal(new Uri("https://gateway.example/pull/s-1"), locator.Of("s-1"));
    }

    /// <summary>
    /// A second mapping is refused rather than taken. A stream STORES its poll address, so two mappings
    /// would leave the streams created between them pointing at the first - a split nothing downstream can
    /// see, since each address is served and each stream looks well-formed.
    /// </summary>
    [Fact]
    public void ASecondMapping_IsRefused()
    {
        var locator = new PollEndpointLocator(BareOptions());
        locator.ServedAt(streamId => new Uri($"{Issuer}/ssf/poll/{streamId}"));

        var refusal = Assert.Throws<InvalidOperationException>(
            () => locator.ServedAt(streamId => new Uri($"{Issuer}/other/poll/{streamId}")));

        Assert.Contains("already mapped", refusal.Message);
    }

    private static SharedSignalsTransmitterOptions BareOptions() => new() { Issuer = Issuer };
}
