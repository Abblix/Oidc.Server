// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Recording where a transmitter's keys are, from the document the transmitter published.
/// </summary>
/// <remarks>
/// What this replaces is a receiver copying the pair out by hand, and both mistakes that copy
/// invites end in the same place - resolution falling through to the well-known convention, which
/// for a transmitter is very likely not its key set, so a signature stops verifying and reads as
/// forgery rather than as wiring.
/// </remarks>
public class JwksKeyResolutionOptionsExtensionsTests
{
    private const string Issuer = "https://transmitter.example.com";

    private static TransmitterConfiguration Document(Uri? jwksUri, string issuer = Issuer)
        => new() { Issuer = issuer, JwksUri = jwksUri };

    /// <summary>The advertised address answers for the advertised issuer.</summary>
    [Fact]
    public void TheAdvertisedPair_IsWhatResolutionUses()
    {
        var advertised = new Uri("https://transmitter.example.com/ssf/jwks");
        var options = new JwksKeyResolutionOptions();

        options.AddSharedSignalsJwksUri(Document(advertised));

        Assert.Equal(advertised, options.JwksUris[Issuer]);
    }

    /// <summary>
    ///     A document without "jwks_uri" is refused, and the refusal names the transmitter.
    /// </summary>
    /// <remarks>
    ///     SSF 1.0 Section 7.1 leaves the field out of the REQUIRED set, so a receiver taking it on
    ///     faith is writing null into a map of addresses. Every SET is signed, which makes such a
    ///     transmitter unverifiable outright - so this is a wiring failure to act on, not a case to
    ///     carry on past. The issuer is in the message because a receiver may hold several.
    /// </remarks>
    [Fact]
    public void ADocumentWithoutAKeySet_IsRefused_AndNamesTheTransmitter()
    {
        var options = new JwksKeyResolutionOptions();

        var failure = Assert.Throws<InvalidOperationException>(
            () => options.AddSharedSignalsJwksUri(Document(jwksUri: null)));

        Assert.Contains(Issuer, failure.Message, StringComparison.Ordinal);
        Assert.Contains(TransmitterConfiguration.ParameterNames.JwksUri, failure.Message, StringComparison.Ordinal);

        // Refused means nothing was written: a half-recorded transmitter would resolve to the
        // convention on the next event and read exactly like one nobody configured.
        Assert.Empty(options.JwksUris);
    }

    /// <summary>Several transmitters are several calls, and none displaces another.</summary>
    /// <remarks>
    /// The property the whole additive shape exists for: two receivers, each learning its own
    /// transmitter, is the ordinary case rather than an exotic one.
    /// </remarks>
    [Fact]
    public void SeveralTransmitters_DoNotDisplaceEachOther()
    {
        const string other = "https://second.example.com";
        var ours = new Uri("https://transmitter.example.com/ssf/jwks");
        var theirs = new Uri("https://second.example.com/keys");

        var options = new JwksKeyResolutionOptions()
            .AddSharedSignalsJwksUri(Document(ours))
            .AddSharedSignalsJwksUri(Document(theirs, other));

        Assert.Equal(ours, options.JwksUris[Issuer]);
        Assert.Equal(theirs, options.JwksUris[other]);
    }

    /// <summary>
    ///     A trailing slash on the advertised issuer does not hide the entry from the events.
    /// </summary>
    /// <remarks>
    ///     The transmitter writes its own "iss" and its own issuer identifier, and SSF 1.0 Section
    ///     7.1 requires them identical - but a document served with the slash and tokens issued
    ///     without it is a real shape, and a lookup that missed would not fail: it would fall
    ///     through to the convention.
    /// </remarks>
    [Fact]
    public void ATrailingSlashOnTheDocument_DoesNotHideTheEntry()
    {
        var advertised = new Uri("https://transmitter.example.com/ssf/jwks");
        var options = new JwksKeyResolutionOptions();

        options.AddSharedSignalsJwksUri(Document(advertised, Issuer + "/"));

        Assert.Equal(advertised, options.JwksUris[Issuer]);
    }
}
