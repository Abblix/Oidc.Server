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
/// Finds the tenants a deployment serves.
/// </summary>
/// <remarks>
/// Asked on every request, so an implementation answers from memory where it can.
/// <para>
/// A tenant's definition does not change while the server runs. What is built from it once - its clients, scopes,
/// resources and pairwise converter - is kept for the tenant's id, so a catalog answering a changed definition
/// under the same id would serve that tenant partly from each. The checks startup runs over tenants judge
/// <see cref="MultiTenancyOptions.Tenants"/>; a catalog of the host's own answering other tenants gets none of them.
/// </para>
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public interface ITenantCatalog
{
    /// <summary>
    /// The tenant registered under <paramref name="tenantId"/>, compared exactly, or null when there is none.
    /// </summary>
    ValueTask<TenantDefinition?> FindByIdAsync(string tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// The tenant served at <paramref name="host"/> and <paramref name="path"/>: the one whose issuer names that
    /// host and, among those, the longest whole-segment start of the path; null when no issuer covers it.
    /// </summary>
    ValueTask<TenantDefinition?> FindByAddressAsync(string host, string path, CancellationToken cancellationToken);
}
