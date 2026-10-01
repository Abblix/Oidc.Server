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
/// Holds the tenants a deployment serves, where every instance of the server reads them.
/// </summary>
/// <remarks>
/// The server reads the whole list at startup and again on a timer (<see cref="MultiTenancyOptions.RefreshEvery"/>),
/// so a tenant the store gains, changes or loses reaches every instance within one period. A tenant the checks of
/// the tenant list refuse is left out and logged, and the others are served. The store assigns each tenant's
/// <see cref="TenantDefinition.Generation"/> when it is created.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public interface ITenantStore
{
    /// <summary>
    /// Every tenant the store holds.
    /// </summary>
    Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken);
}
