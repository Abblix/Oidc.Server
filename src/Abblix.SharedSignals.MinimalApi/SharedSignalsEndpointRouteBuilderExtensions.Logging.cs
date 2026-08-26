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
    /// JWTs." This package always signs - <c>AddSecurityEvents</c> refuses to start without a signing key
    /// source, and every SET goes through the signer - so there is no deployment here for which the
    /// member is genuinely optional. The CAEP profile says the same thing unconditionally in Section
    /// 2.3.3, and Section 2.4.2 sends a receiver to this member for the keys.
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
}
