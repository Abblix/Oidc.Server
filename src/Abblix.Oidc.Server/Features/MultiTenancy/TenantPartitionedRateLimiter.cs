// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Threading.RateLimiting;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Spends a budget the server keeps per caller - failed client authentications, introspection and revocation
/// requests - separately for each tenant.
/// </summary>
/// <remarks>
/// The budget is partitioned by what it is spent on, a client id or a source address, which two tenants can share:
/// without this, attempts against one tenant's client would spend another tenant's client of the same id. Each
/// tenant gets a limiter of its own, built the way the budget was registered, so the resource reaches it as the
/// server produced it - a host's own limiter partitions by the address or client it was written for.
/// </remarks>
/// <param name="createLimiter">Builds a new limiter for a tenant that has none yet.</param>
/// <param name="tenantAccessor">Names the tenant a budget is spent for.</param>
/// <typeparam name="TResource">What the budget is partitioned by.</typeparam>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantPartitionedRateLimiter<TResource>(
    Func<PartitionedRateLimiter<TResource>> createLimiter,
    ITenantAccessor tenantAccessor) : PartitionedRateLimiter<TResource>
{
    // Lazy, so two first calls of one tenant racing each other still build one limiter between them
    private readonly ConcurrentDictionary<string, Lazy<PartitionedRateLimiter<TResource>>> _limiters =
        new(StringComparer.Ordinal);

    private PartitionedRateLimiter<TResource> Current
        => _limiters.GetOrAdd(TenantKey.CurrentTenantId(tenantAccessor), _ => new(createLimiter)).Value;

    /// <inheritdoc />
    public override RateLimiterStatistics? GetStatistics(TResource resource)
        => Current.GetStatistics(resource);

    /// <inheritdoc />
    protected override RateLimitLease AttemptAcquireCore(TResource resource, int permitCount)
        => Current.AttemptAcquire(resource, permitCount);

    /// <inheritdoc />
    protected override ValueTask<RateLimitLease> AcquireAsyncCore(
        TResource resource,
        int permitCount,
        CancellationToken cancellationToken)
        => Current.AcquireAsync(resource, permitCount, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Each tenant's limiter was built for this one alone, so it goes with it.</remarks>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            foreach (var limiter in Built)
                limiter.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc />
    protected override async ValueTask DisposeAsyncCore()
    {
        foreach (var limiter in Built)
            await limiter.DisposeAsync();
    }

    private IEnumerable<PartitionedRateLimiter<TResource>> Built
        => _limiters.Values.Where(limiter => limiter.IsValueCreated).Select(limiter => limiter.Value);
}
