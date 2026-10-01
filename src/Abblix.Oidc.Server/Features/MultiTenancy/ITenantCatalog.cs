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
/// What is built from a tenant's definition - its scopes, resources, pairwise converter and clients - is kept for
/// the tenant and built again once the definition hands out other objects for them. So a catalog answers with the
/// same objects until the definition really changes: one building a fresh definition for every lookup has all of
/// them rebuilt on every request. With the server's own catalog (<see cref="StoreTenantCatalog"/>) what was built is
/// replaced only from the definition it serves now, so a request still holding one it replaced is answered with what
/// was built; with any other catalog, one wrapping the server's own included, such a request builds them back from
/// the definition it holds. The checks of the tenant list judge what the server's own catalog reads, so a catalog
/// of the host's own gets none of them, while one wrapping the server's passes on only what they let through.
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
