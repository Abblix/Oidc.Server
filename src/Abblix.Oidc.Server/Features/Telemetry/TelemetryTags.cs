// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Every attribute the server puts on a span or a measurement. Each but <see cref="ClientId"/> takes its values from a
/// closed set, and none carries a token, a code, a secret or anything about the end user.
/// </summary>
/// <remarks>
/// Spans and log records name the client a request is served for; measurements do not, since one series per client
/// would grow with every client registered. The end user is never named on a span or a measurement: a log record of
/// a successful operation names the subject only by its fingerprint.
/// </remarks>
public static class TelemetryTags
{
    /// <summary>
    /// The client an endpoint's span serves, set once the client is authenticated or found by the client_id it is
    /// registered under, and never put on a measurement. OpenTelemetry's conventions name no attribute for an OAuth
    /// client (their <c>client.*</c> attributes describe the network peer), so it is named here, beside the other
    /// OAuth attributes.
    /// </summary>
    public const string ClientId = "oauth.client_id";

    /// <summary>
    /// The endpoint a span serves, one of <see cref="TelemetryEndpoints"/>.
    /// </summary>
    public const string Endpoint = "oidc.endpoint";

    /// <summary>
    /// The tenant serving the request.
    /// </summary>
    public const string Tenant = "oidc.tenant";

    /// <summary>
    /// The grant type of a token request, when it is one the server supports; on a token the authorization endpoint
    /// hands out through the front channel, <c>implicit</c>, which then counts the hybrid flow's tokens too, since
    /// the protocol names no grant type of its own for them.
    /// </summary>
    public const string GrantType = "oauth.grant_type";

    /// <summary>
    /// The response type of an authorization request, its values ordered and space-separated, when each is one the
    /// protocol defines.
    /// </summary>
    public const string ResponseType = "oauth.response_type";

    /// <summary>
    /// The error code a refused request is answered with, when it is one of the library's error codes, and
    /// <see cref="Other"/> otherwise; <see cref="ClientMetadataUnavailable"/> for a refusal whose client metadata
    /// document could not be had for now.
    /// </summary>
    public const string Error = "oauth.error";

    /// <summary>
    /// The <see cref="Error"/> of a request answered 503 because a client metadata document could not be had for now
    /// (<see cref="Common.ClientTemporarilyUnavailableError"/>, experimental), told apart from a spent budget, which is
    /// answered 429 and named temporarily_unavailable.
    /// </summary>
    public const string ClientMetadataUnavailable = "client_metadata_unavailable";

    /// <summary>
    /// The value of an attribute whose value is not one of its closed set, as a host's own handler or limiter may
    /// produce.
    /// </summary>
    public const string Other = "other";

    /// <summary>
    /// The type of the exception a request failed with, as OpenTelemetry's general conventions name it.
    /// </summary>
    public const string ErrorType = "error.type";

    /// <summary>
    /// How the handling of a request ended, one of <see cref="TelemetryOutcomes"/>.
    /// </summary>
    public const string Outcome = "oidc.outcome";

    /// <summary>
    /// The stage of handling a request a child span runs, one of <see cref="TelemetryStages"/>.
    /// </summary>
    public const string Stage = "oidc.stage";

    /// <summary>
    /// The operation of the server's entity storage a measurement records, one of
    /// <see cref="TelemetryStorageOperations"/>.
    /// </summary>
    public const string StorageOperation = "oidc.storage.operation";

    /// <summary>
    /// The response parameter a token is handed out in, one of <see cref="TelemetryTokenTypes"/>.
    /// </summary>
    public const string TokenType = "oidc.token_type";

    /// <summary>
    /// The JWS algorithm a token is signed with, one of the server's own signing algorithms.
    /// </summary>
    public const string SigningAlgorithm = "oidc.signing.alg";

    /// <summary>
    /// The budget a refused caller has spent, one of the keys of
    /// <see cref="RateLimiting.CallerRateLimiters"/>, and <see cref="Other"/> for a budget of the host's own.
    /// </summary>
    public const string RateLimitBudget = "oidc.rate_limit.budget";

    /// <summary>
    /// The term of the license that refused a request, one of <see cref="LicenseRefusalReasons"/>.
    /// </summary>
    public const string LicenseRefusalReason = "oidc.license.reason";
}
