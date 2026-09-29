// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading;
using System.Threading.RateLimiting;
using System.Threading.Tasks;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// A host's own limiter of failed authentications, registered by its type, which grants every permit and writes
/// down what it was asked for.
/// </summary>
public sealed class HostLimiter : PartitionedRateLimiter<string>
{
    private readonly PartitionedRateLimiter<string> _inner =
        PartitionedRateLimiter.Create<string, string>(address => RateLimitPartition.GetNoLimiter(address));

    private readonly HostLimiterLog _log;

    public HostLimiter(HostLimiterLog log)
    {
        _log = log;
        _log.Built++;
    }

    public override RateLimiterStatistics? GetStatistics(string resource) => _inner.GetStatistics(resource);

    protected override RateLimitLease AttemptAcquireCore(string resource, int permitCount)
    {
        _log.Seen.Add(resource);
        return _inner.AttemptAcquire(resource, permitCount);
    }

    protected override ValueTask<RateLimitLease> AcquireAsyncCore(
        string resource, int permitCount, CancellationToken cancellationToken)
    {
        _log.Seen.Add(resource);
        return _inner.AcquireAsync(resource, permitCount, cancellationToken);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _inner.Dispose();

        base.Dispose(disposing);
    }
}
