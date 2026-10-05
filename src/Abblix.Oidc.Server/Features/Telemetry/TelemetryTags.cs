// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Every attribute the server puts on a span. Each takes its values from a closed set, so no attribute carries a
/// token, a code, a secret or anything about the end user.
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
    /// The grant type of a token request, when it is one the server supports.
    /// </summary>
    public const string GrantType = "oauth.grant_type";

    /// <summary>
    /// The response type of an authorization request, its values ordered and space-separated, when each is one the
    /// protocol defines.
    /// </summary>
    public const string ResponseType = "oauth.response_type";

    /// <summary>
    /// The error code a refused request is answered with, when it is one of the library's error codes, and
    /// <see cref="UnknownError"/> otherwise.
    /// </summary>
    public const string Error = "oauth.error";

    /// <summary>
    /// The value of <see cref="Error"/> for an error code the library does not define, as a host's own handler may
    /// answer with.
    /// </summary>
    public const string UnknownError = "other";

    /// <summary>
    /// The type of the exception a request failed with, as OpenTelemetry's general conventions name it.
    /// </summary>
    public const string ErrorType = "error.type";
}
