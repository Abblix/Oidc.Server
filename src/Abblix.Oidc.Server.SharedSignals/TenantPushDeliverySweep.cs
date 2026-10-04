// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Runs the push delivery pass once for each tenant the server serves, inside that tenant.
/// </summary>
/// <remarks>
/// The pass runs on a timer, outside any request, so nothing names a tenant for it; without this it would find
/// no streams, since every stream belongs to one. One tenant's failure is logged and the others still run.
/// </remarks>
/// <param name="logger">Records a tenant whose pass failed.</param>
/// <param name="inner">The pass over one tenant's streams.</param>
/// <param name="catalog">Names the tenants served now.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed partial class TenantPushDeliverySweep(
    ILogger<TenantPushDeliverySweep> logger,
    IPushDeliverySweep inner,
    StoreTenantCatalog catalog) : IPushDeliverySweep
{
    /// <inheritdoc />
    public async Task SweepAsync(CancellationToken cancellationToken)
    {
        foreach (var tenant in catalog.ServedTenants.ToArray())
        {
            using var scope = TenantScope.Enter(tenant);
            try
            {
                await inner.SweepAsync(cancellationToken);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                LogTenantSweepFailed(exception, tenant.Id);
            }
        }
    }
}
