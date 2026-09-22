// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.RateLimiting;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.RateLimiting;

/// <summary>
/// Bounds what a sender that never authenticates successfully can cost every endpoint that authenticates
/// a client, by counting failed client authentications against the address they came from.
/// </summary>
/// <remarks>
/// The per-client budget cannot reach this: it is charged once the caller has proven which client it is, and a
/// sender whose credentials never verify never gets that far. Its requests are not free - a client assertion is
/// a signature this server verifies before it can say the credential is wrong - so the failures are counted and
/// a source over its budget is refused before its next credential is looked at.
/// <para>
/// Only failures are counted, which is what keeps this away from working clients: their authentications succeed,
/// so they never charge it however busy they are. A source whose address cannot be determined is not counted
/// either, because one bucket for every such request would let a single sender close the endpoints to everybody.
/// </para>
/// </remarks>
/// <param name="limiter">The budget of failures one address gets, which a host may register itself.</param>
/// <param name="requestInfoProvider">Names the address a request came from.</param>
public sealed class AuthenticationFailureBudget(
    [FromKeyedServices(CallerRateLimiters.AuthenticationFailures)] PartitionedRateLimiter<string> limiter,
    IRequestInfoProvider requestInfoProvider)
{
    /// <summary>
    /// Answers whether this request's source has already spent its budget, without spending anything itself.
    /// </summary>
    /// <returns>The refusal to return to the caller, or null when its credentials may be looked at.</returns>
    public TooManyRequestsError? RefuseIfSpent()
    {
        if (Source is not { } source)
            return null;

        // Acquiring nothing is how the platform's limiter is asked whether a permit is available: it answers
        // from the same window the failures are counted in and leaves the count where it is, so a source that
        // is still within its budget is not charged for being checked.
        using var available = limiter.AttemptAcquire(source, permitCount: 0);
        if (available.IsAcquired)
            return null;

        return new TooManyRequestsError(
            "Too many failed client authentications from this source",
            available.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) ? retryAfter : null);
    }

    /// <summary>
    /// Charges one failed authentication to this request's source.
    /// </summary>
    public void RecordFailure()
    {
        if (Source is { } source)
            limiter.AttemptAcquire(source).Dispose();
    }

    /// <summary>
    /// The address this request came from, or null when the server cannot name one - which is also when
    /// nothing is counted.
    /// </summary>
    internal string? Source => requestInfoProvider.SourceName();
}
