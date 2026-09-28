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
/// Finds the tenants a deployment serves, by identifier and by host name.
/// </summary>
/// <remarks>
/// Asked on every request, so an implementation answers from memory where it can.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public interface ITenantCatalog
{
    /// <summary>
    /// The tenant registered under <paramref name="tenantId"/>, compared exactly, or null when there is none.
    /// </summary>
    ValueTask<TenantDefinition?> FindByIdAsync(string tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// The tenant bound to <paramref name="host"/>, compared as <see cref="TenantHost.Normalize"/> leaves it, or
    /// null when no tenant is bound to it.
    /// </summary>
    ValueTask<TenantDefinition?> FindByHostAsync(string host, CancellationToken cancellationToken);
}
