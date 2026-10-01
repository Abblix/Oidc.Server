// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Reads the store of tenants before the server serves anything, and again every
/// <see cref="MultiTenancyOptions.RefreshEvery"/>, so a tenant another instance created, changed or removed reaches
/// this one within that period.
/// </summary>
/// <remarks>
/// A store that cannot be read at startup stops the process: there is nobody yet to serve. Afterwards a failed
/// reading keeps the tenants of the last one and is logged, since taking the process down would turn an outage of
/// the store into an outage of every tenant.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal sealed partial class TenantCatalogRefreshService(
    ILogger<TenantCatalogRefreshService> logger,
    StoreTenantCatalog catalog,
    ITenantCatalog served,
    IOptions<MultiTenancyOptions> options,
    TimeProvider timeProvider) : BackgroundService
{
    // A host serving tenants from a catalog of its own reads no store of tenants
    private bool Serving => ReferenceEquals(served, catalog);

    /// <inheritdoc />
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!Serving)
            return;

        await catalog.RefreshAsync(cancellationToken);
        await base.StartAsync(cancellationToken);
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var period = options.Value.RefreshEvery;
        using var timer = new PeriodicTimer(period, timeProvider);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    await catalog.RefreshAsync(stoppingToken);
                }
                catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
                {
                    LogRefreshFailed(exception, period);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // The host stopping, or disposed without stopping first, ends the wait; neither is a failure to report
        }
    }
}
