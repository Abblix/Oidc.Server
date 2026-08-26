// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SharedSignals;
using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.MinimalApi;

public static partial class SharedSignalsEndpointRouteBuilderExtensions
{
    /// <summary>
    /// The configuration document names no key location, so nothing a receiver reads leads to a key.
    /// </summary>
    /// <remarks>
    /// Shared Signals Framework 1.0 Section 7.1 marks "jwks_uri" OPTIONAL and then attaches a condition
    /// two sentences later: "This value MUST be specified if the Transmitter intends to generate signed
    /// JWTs." This package always signs: <c>EventDispatcher</c> takes the signer as a required
    /// dependency and every event it sends goes through it, so a transmitter that emits anything at all
    /// has signed it. (Not because startup refuses a host with no key: that refusal lives in a factory
    /// body and fires on the first resolve, and a host supplying its own signer never reaches it - either
    /// way what comes out is signed.) The CAEP profile says the same thing unconditionally in Section
    /// 2.3.3 of draft 01, and Section 2.4.2 sends a receiver to this member for the keys.
    /// <para>
    /// A warning rather than a refusal because the transmitter is otherwise functional and the host may
    /// be mid-configuration; nothing here can distribute a key on its behalf. Said once, at startup,
    /// because it is a property of the configuration rather than of any request.
    /// </para>
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Transmitter.NoJwksUriAdvertised,
        Level = LogLevel.Warning,
        Message = "The transmitter configuration document advertises no jwks_uri, so a receiver has "
            + "nowhere to fetch this transmitter's signing keys and cannot verify any event. This "
            + "transmitter signs every SET, which makes the member required by Shared Signals Framework "
            + "1.0 Section 7.1 as well as by the CAEP Interoperability Profile 1.0 Section 2.3.3. Set "
            + "SharedSignalsTransmitterOptions.JwksUri to where the JWK Set is published.")]
    private static partial void LogNoJwksUriAdvertised(ILogger logger);

    /// <summary>
    /// The host replaced the advertised schemes and left out the one the profile requires.
    /// </summary>
    /// <remarks>
    /// Only reachable when the host supplies a non-empty list of its own. Leaving the option unset takes
    /// the default, which IS that entry; setting it to an empty list advertises nothing and is read as a
    /// deliberate choice, so neither is warned about.
    /// <para>
    /// A warning rather than a refusal: unlike jwks_uri, Shared Signals Framework 1.0 attaches no
    /// condition to this member, so a deployment authorizing its Stream Management API by something
    /// other than OAuth 2.0 is outside the CAEP profile and correct under SSF. This package does not
    /// perform the authorization in any case.
    /// </para>
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Transmitter.OAuthSchemeNotAdvertised,
        Level = LogLevel.Warning,
        Message = "The {SchemeCount} configured authorization scheme(s) name no OAuth 2.0, which the CAEP "
            + "Interoperability Profile 1.0 Section 2.3.7 requires authorization_schemes to include as "
            + "{{\"spec_urn\": \"urn:ietf:rfc:6749\"}}. Add it, or leave "
            + "SharedSignalsTransmitterOptions.AuthorizationSchemes unset to advertise it alone.")]
    private static partial void LogOAuthSchemeNotAdvertised(ILogger logger, int SchemeCount);

    /// <summary>
    /// The management API checks no scope, because the host supplied no way to read the granted ones.
    /// </summary>
    /// <remarks>
    /// The sharpest of the three, because the other two are visible in the document a receiver fetches
    /// while this one is not. The configuration metadata advertises OAuth 2.0 by default, so a receiver
    /// is told the Stream Management API is OAuth-protected; with no selector, every token that gets past
    /// the host's own authentication may do everything, and nothing anywhere says so. That is the whole
    /// of Section 2.7.2's sufficiency MUST switched off.
    /// <para>
    /// A warning rather than a refusal for the same reason as the others: a deployment authorizing by
    /// something this package cannot read is working and outside the profile, which is its choice to
    /// make - but not one it should make without noticing.
    /// </para>
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Transmitter.ScopeCheckingDisabled,
        Level = LogLevel.Warning,
        Message = "No scope is checked on the Stream Management API: "
            + "SharedSignalsEndpointOptions.GrantedScopesSelector is unset, so this transmitter cannot "
            + "read what a caller's token was granted and every authenticated caller may do everything. "
            + "The CAEP Interoperability Profile 1.0 Section 2.7.2 requires the transmitter to verify "
            + "that the token is sufficient for the requested action, and Section 2.7.3 defines "
            + "ssf.read and ssf.manage as what sufficient means.")]
    private static partial void LogScopeCheckingDisabled(ILogger logger);

    /// <summary>
    /// A new stream covers no subject until the receiver names one, and a receiver following the profile
    /// never will.
    /// </summary>
    /// <remarks>
    /// The quietest of the set, and the reason it is worth saying out loud. Nothing is refused and nothing
    /// is logged at delivery: the dispatcher matches no stream, answers zero, and a receiver that is doing
    /// exactly what Section 2.4.4 tells it to do waits forever on a stream that reads as healthy on both
    /// sides. There is no error on the wire and nothing in the stream status to distinguish it from a quiet
    /// period.
    /// <para>
    /// A warning rather than a refusal, and the default is not flipped, because the two readings are both
    /// defensible: covering nothing until a subject is named is what keeps a misconfigured stream from
    /// leaking, and covering everything is what an interoperable transmitter does. The profile binds only
    /// the receiver here - Section 2.3 imposes no mirror - so this is a deployment's choice, and the only
    /// thing wrong with it was that it was made silently.
    /// </para>
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Transmitter.NoSubjectsIncludedByDefault,
        Level = LogLevel.Warning,
        Message = "New streams will cover no subject: "
            + "SharedSignalsTransmitterOptions.DefaultSubjectsMode is None, so a stream delivers only to "
            + "subjects added through the Add Subject API. The CAEP Interoperability Profile 1.0 Section "
            + "2.4.4 tells a receiver to \"assume that all subjects are implicitly included in a Stream, "
            + "without any Add Subject method invocations\", so a conformant receiver adds none and "
            + "receives nothing, silently. Set DefaultSubjectsMode to All, or keep None knowing that this "
            + "transmitter expects its receivers to name their subjects.")]
    private static partial void LogNoSubjectsIncludedByDefault(ILogger logger);
}
