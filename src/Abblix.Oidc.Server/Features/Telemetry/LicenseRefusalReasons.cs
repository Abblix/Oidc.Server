// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The values of <see cref="TelemetryTags.LicenseRefusalReason"/>.
/// </summary>
public static class LicenseRefusalReasons
{
    /// <summary>
    /// The license names the issuers it covers, and the request's issuer is not one of them.
    /// </summary>
    public const string IssuerNotAllowed = "issuer_not_allowed";

    /// <summary>
    /// The server serves more issuers than the license allows.
    /// </summary>
    public const string IssuerLimit = "issuer_limit";

    /// <summary>
    /// The server issues tokens to more clients than the license allows, beyond its margin.
    /// </summary>
    public const string ClientLimit = "client_limit";
}
