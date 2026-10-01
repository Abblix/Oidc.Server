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

    // Every limiter handed to a tenant, by identity: adding to it is the check, so two tenants building at once
    // cannot both find it absent
    private readonly ConcurrentDictionary<object, byte> _handedOut = new(ReferenceEqualityComparer.Instance);

    private PartitionedRateLimiter<TResource> Current
        => _limiters.GetOrAdd(TenantKey.CurrentSpace(tenantAccessor), _ => new(Build)).Value;

    /// <summary>
    /// A new limiter for a tenant, refused when it is one another tenant already holds.
    /// </summary>
    /// <remarks>
    /// A registration can build its limiter by handing out one it keeps, and then the tenants would spend one
    /// budget between them. Nothing earlier can see that: the registration is a factory until it is called.
    /// </remarks>
    private PartitionedRateLimiter<TResource> Build()
    {
        var limiter = createLimiter();
        if (!_handedOut.TryAdd(limiter, default))
        {
            throw new InvalidOperationException(
                "The registration of this budget handed out a limiter it had already given another tenant, so the " +
                "two tenants would spend one budget. Register a factory or a type that builds a new limiter on " +
                "every call.");
        }

        return limiter;
    }

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
            foreach (var limiter in HandedOut)
                limiter.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc />
    protected override async ValueTask DisposeAsyncCore()
    {
        foreach (var limiter in HandedOut)
            await limiter.DisposeAsync();
    }

    private IEnumerable<PartitionedRateLimiter<TResource>> HandedOut
        => _handedOut.Keys.Cast<PartitionedRateLimiter<TResource>>();
}
