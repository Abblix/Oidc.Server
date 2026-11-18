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
/// <para>
/// Each tenant is served with the definition the catalog the server resolves tenants through serves it with now, as a
/// request reaching the tenant would be. With a catalog of the host's own, the transmitter is built once and signs as
/// the definition last served to it, so a pass that did not serve one would sign as the issuer and keys the tenant
/// had before its last move or key change on this instance. A tenant that catalog no longer serves is passed over, as
/// a request reaching it is.
/// </para>
/// </remarks>
/// <param name="logger">Records a tenant whose pass failed.</param>
/// <param name="transmitters">The transmitter of each tenant, whose pass runs over that tenant's streams.</param>
/// <param name="catalog">Names the tenants served now.</param>
/// <param name="served">The catalog the server resolves tenants through, the host's own where it registered one.
/// </param>
internal sealed partial class TenantPushDeliverySweep(
    ILogger<TenantPushDeliverySweep> logger,
    TenantTransmitters transmitters,
    StoreTenantCatalog catalog,
    ITenantCatalog served) : IPushDeliverySweep
{
    /// <inheritdoc />
    public async Task SweepAsync(CancellationToken cancellationToken)
    {
        foreach (var tenantId in catalog.ServedTenants.Select(listed => listed.Id).ToArray())
        {
            try
            {
                if (await served.FindByIdAsync(tenantId, cancellationToken) is not { } tenant)
                    continue;

                using var scope = TenantScope.Enter(tenant);
                await transmitters.Serving(tenant).Sweep.SweepAsync(cancellationToken);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                LogTenantSweepFailed(exception, tenantId);
            }
        }
    }
}
