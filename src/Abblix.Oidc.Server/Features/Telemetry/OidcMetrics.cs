// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The instruments the server records into its meter, named <see cref="OidcTelemetry.SourceName"/>, which a host
/// passes to its OpenTelemetry setup to receive them:
/// <c>AddOpenTelemetry().WithMetrics(m =&gt; m.AddMeter(OidcTelemetry.SourceName))</c>.
/// </summary>
/// <remarks>
/// No instrument carries a client or subject identifier: every dimension takes its values from a closed set named
/// in <see cref="TelemetryTags"/>.
/// </remarks>
public static class OidcMetrics
{
    /// <summary>
    /// A histogram of the seconds the server takes to handle a request of an endpoint, by
    /// <see cref="TelemetryTags.Endpoint"/>, <see cref="TelemetryTags.Outcome"/>, <see cref="TelemetryTags.Error"/>
    /// and <see cref="TelemetryTags.Tenant"/>. Its count is the number of requests of the endpoints
    /// <see cref="TelemetryEndpoints"/> names; the key set is served as it stands and is not among them, so a host
    /// sees it in its own HTTP measurements.
    /// </summary>
    public const string RequestDuration = "oidc.request.duration";

    /// <summary>
    /// A counter of the tokens the server hands out, by <see cref="TelemetryTags.TokenType"/>,
    /// <see cref="TelemetryTags.GrantType"/> and <see cref="TelemetryTags.Tenant"/>: at the token endpoint, in a CIBA
    /// push delivery, and through the front channel of the authorization endpoint. A token is counted when it is
    /// minted, so one a push delivery fails to bring to the client is counted too.
    /// </summary>
    public const string TokensIssued = "oidc.tokens.issued";

    /// <summary>
    /// A histogram of the seconds signing one token takes, by <see cref="TelemetryTags.SigningAlgorithm"/>; a key
    /// held by an external custodian shows here as the round trip to it. A token left unsigned is not recorded.
    /// </summary>
    public const string TokenSigningDuration = "oidc.token.signing.duration";

    /// <summary>
    /// A counter of dynamic client registration requests, by <see cref="TelemetryTags.Outcome"/>, a registration
    /// ending in an exception included.
    /// </summary>
    public const string ClientsRegistered = "oidc.clients.registered";

    /// <summary>
    /// A counter of requests the license refused, by <see cref="TelemetryTags.LicenseRefusalReason"/>.
    /// </summary>
    public const string LicenseRefusals = "oidc.license.refusals";

    /// <summary>
    /// A counter of requests refused for a spent budget, by <see cref="TelemetryTags.Endpoint"/> and
    /// <see cref="TelemetryTags.RateLimitBudget"/>.
    /// </summary>
    public const string RateLimitRefusals = "oidc.rate_limit.refusals";
}
