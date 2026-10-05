// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Every attribute the server puts on a span or a measurement. Each takes its values from a closed set, so no
/// attribute carries a token, a code, a secret or anything about the end user.
/// </summary>
public static class TelemetryTags
{
    /// <summary>
    /// The endpoint a span serves, one of <see cref="TelemetryEndpoints"/>.
    /// </summary>
    public const string Endpoint = "oidc.endpoint";

    /// <summary>
    /// The tenant serving the request, under multi-tenancy; absent on a server without tenants.
    /// </summary>
    public const string Tenant = "oidc.tenant";

    /// <summary>
    /// The grant type of a token request, when it is one the server supports; on a token the authorization endpoint
    /// hands out, <c>implicit</c>.
    /// </summary>
    public const string GrantType = "oauth.grant_type";

    /// <summary>
    /// The response type of an authorization request, its values ordered and space-separated, when each is one the
    /// protocol defines.
    /// </summary>
    public const string ResponseType = "oauth.response_type";

    /// <summary>
    /// The error code a refused request is answered with, when it is one of the library's error codes, and
    /// <see cref="Other"/> otherwise.
    /// </summary>
    public const string Error = "oauth.error";

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
