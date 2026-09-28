// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Finds the tenants a deployment serves, by identifier and by host name.
/// </summary>
public interface ITenantCatalog
{
    /// <summary>
    /// The tenant registered under <paramref name="tenantId"/>, compared exactly, or null when there is none.
    /// </summary>
    Task<TenantDefinition?> FindByIdAsync(string tenantId);

    /// <summary>
    /// The tenant bound to <paramref name="host"/>, compared without regard to case, or null when no tenant
    /// is bound to it.
    /// </summary>
    Task<TenantDefinition?> FindByHostAsync(string host);
}
