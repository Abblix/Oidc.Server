// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Threading.RateLimiting;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Spends a budget the server keeps per caller - failed client authentications, introspection and revocation
/// requests - separately for each tenant.
/// </summary>
/// <remarks>
/// The budget is partitioned by what it is spent on, a client id or a source address, which two tenants can share:
/// without this, attempts against one tenant's client would spend another tenant's client of the same id. The
/// tenant goes into the resource the budget is partitioned by, so one limiter keeps every tenant's partitions.
/// </remarks>
/// <typeparam name="TResource">What the budget is partitioned by.</typeparam>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public abstract class TenantPartitionedRateLimiter<TResource>(PartitionedRateLimiter<TResource> inner)
    : PartitionedRateLimiter<TResource>
{
    /// <summary>
    /// <paramref name="resource"/> within the current tenant.
    /// </summary>
    protected abstract TResource Scope(TResource resource);

    /// <inheritdoc />
    public override RateLimiterStatistics? GetStatistics(TResource resource)
        => inner.GetStatistics(Scope(resource));

    /// <inheritdoc />
    protected override RateLimitLease AttemptAcquireCore(TResource resource, int permitCount)
        => inner.AttemptAcquire(Scope(resource), permitCount);

    /// <inheritdoc />
    protected override ValueTask<RateLimitLease> AcquireAsyncCore(
        TResource resource,
        int permitCount,
        CancellationToken cancellationToken)
        => inner.AcquireAsync(Scope(resource), permitCount, cancellationToken);

    /// <inheritdoc />
    /// <remarks>The inner limiter was built for this one alone, so it goes with it.</remarks>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
            inner.Dispose();

        base.Dispose(disposing);
    }

    /// <inheritdoc />
    protected override ValueTask DisposeAsyncCore() => inner.DisposeAsync();
}
