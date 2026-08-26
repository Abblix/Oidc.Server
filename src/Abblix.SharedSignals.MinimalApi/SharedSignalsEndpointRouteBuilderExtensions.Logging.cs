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
    /// A warning rather than a refusal, because Shared Signals Framework 1.0 leaves "jwks_uri" optional
    /// and permits key distribution by out-of-band agreement. The CAEP Interoperability Profile does not:
    /// Section 2.4.2 sends a receiver to this member for the signing keys, so under that profile a
    /// receiver reaching this transmitter can verify nothing at all. Said once, at startup, because it is
    /// a property of the configuration rather than of any request.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Transmitter.NoJwksUriAdvertised,
        Level = LogLevel.Warning,
        Message = "The transmitter configuration document advertises no jwks_uri, so a receiver has "
            + "nowhere to fetch this transmitter's signing keys and cannot verify any event. Shared "
            + "Signals Framework 1.0 allows this and the CAEP Interoperability Profile 1.0 Section 2.3.3 "
            + "does not. Set SharedSignalsTransmitterOptions.JwksUri to where the JWK Set is published.")]
    private static partial void LogNoJwksUriAdvertised(ILogger logger);

    /// <summary>
    /// The host replaced the advertised schemes and left out the one the profile requires.
    /// </summary>
    /// <remarks>
    /// Only reachable when the host supplies its own list, since the default IS that entry. Also a
    /// warning: a deployment authorizing its Stream Management API by something other than OAuth 2.0 is
    /// outside the profile but not broken, and this package does not perform the authorization anyway.
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
