// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Shared identifiers the HTTP transport adapters (MVC, Minimal API) agree on. The core declares them so both
/// adapters reference one value rather than each carrying its own copy.
/// </summary>
public static class OidcConstants
{
    /// <summary>
    /// The name of the CORS policy applied to the cross-origin OIDC endpoints. The host registers a policy under this
    /// name (and calls <c>UseCors</c>); both transport adapters apply the same name so a host can share one policy.
    /// </summary>
    public const string CorsPolicyName = "OidcCorsPolicy";
}
