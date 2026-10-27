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
/// Runs the push delivery pass of each tenant the server serves, through that tenant's own transmitter.
/// </summary>
/// <remarks>
/// The pass runs on a timer, outside any request, so each tenant's pass runs inside that tenant's scope: its
/// transmitter refuses to serve while any other tenant is, and a sweep a host sets off from one tenant's request
/// still runs every tenant's pass. One tenant's failure is logged and the others still run.
/// </remarks>
/// <param name="logger">Records a tenant whose pass failed.</param>
/// <param name="transmitters">The transmitter of each tenant, whose pass runs over that tenant's streams.</param>
/// <param name="catalog">Names the tenants served now.</param>
internal sealed partial class TenantPushDeliverySweep(
    ILogger<TenantPushDeliverySweep> logger,
    TenantTransmitters transmitters,
    StoreTenantCatalog catalog) : IPushDeliverySweep
{
    /// <inheritdoc />
    public async Task SweepAsync(CancellationToken cancellationToken)
    {
        foreach (var tenant in catalog.ServedTenants.ToArray())
        {
            try
            {
                using var scope = TenantScope.Enter(tenant);
                await transmitters.For(tenant).Sweep.SweepAsync(cancellationToken);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                LogTenantSweepFailed(exception, tenant.Id);
            }
        }
    }
}
