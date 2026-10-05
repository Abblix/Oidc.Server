// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Why <see cref="ITenantManager"/> refused a change of the tenants.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public enum TenantChangeRefusalReason
{
    /// <summary>
    /// The tenants as the change would leave them fail a check the server runs at startup.
    /// </summary>
    Invalid,

    /// <summary>
    /// The store holds a tenant under the id already.
    /// </summary>
    AlreadyExists,

    /// <summary>
    /// The store holds no tenant under the id.
    /// </summary>
    NotFound,

    /// <summary>
    /// The tenant was changed since it was read: read it again and decide on the change once more.
    /// </summary>
    Conflict,

    /// <summary>
    /// The license in force allows no more issuers than the tenants the store already holds, and each tenant is one.
    /// </summary>
    /// <remarks>
    /// A removed tenant frees its place for the license only once the server releases it, so a tenant created
    /// right after a removal can still take the server past the limit until then.
    /// </remarks>
    BeyondLicense,
}
