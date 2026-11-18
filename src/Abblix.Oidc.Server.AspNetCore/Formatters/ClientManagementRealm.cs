// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>
/// The realm the Bearer challenge of a client registration or client configuration answer carries.
/// </summary>
internal static class ClientManagementRealm
{
    /// <summary>
    /// The issuer for a request lacking authentication information, whose challenge carries no error attributes
    /// (RFC 6750 section 3.1) and still needs one, since section 3 has the scheme "followed by one or more auth-param
    /// values"; none for any other refusal, whose error attributes are the challenge's parameters.
    /// </summary>
    /// <param name="error">The refusal the challenge answers.</param>
    /// <param name="tenantAccessor">Names the tenant the request is served at, whose issuer is the realm.</param>
    public static string? Of(OidcError error, ITenantAccessor tenantAccessor)
        => error is MissingAuthenticationError ? tenantAccessor.CurrentTenant().Issuer.OriginalString : null;
}
