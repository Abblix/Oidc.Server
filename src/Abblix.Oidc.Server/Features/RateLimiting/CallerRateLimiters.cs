// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.RateLimiting;
using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.RateLimiting;

/// <summary>
/// The per-caller budgets the token-reading endpoints spend, kept as <see cref="PartitionedRateLimiter{TResource}"/>
/// instances registered under the keys below, one per endpoint, partitioned by client identifier.
/// </summary>
/// <remarks>
/// The type is the one from <c>System.Threading.RateLimiting</c> rather than an interface of ours, so a host that
/// needs a different policy - a token bucket, a sliding window, a limiter that counts across several nodes -
/// registers the platform's own abstraction under the same key and this server spends that budget instead. ASP.NET
/// Core's rate-limiting middleware cannot serve here: it runs before the request reaches the endpoint, where the
/// caller is still whoever holds the socket, and the whole point of this budget is that it is charged to the
/// client the request authenticated as.
/// <para>
/// A budget is taken with a single attempt that never waits, so a substituted limiter configured to queue does
/// not queue here: a caller it would have held is refused instead. An endpoint holding a request open is the
/// thing this feature exists to stop, so the queue a host configured for its own callers is deliberately not
/// honoured on this path.
/// </para>
/// </remarks>
public static class CallerRateLimiters
{
    /// <summary>
    /// The dependency-injection key of the budget spent by RFC 7662 introspection requests.
    /// </summary>
    public const string Introspection = "Abblix.Oidc.Server.Introspection.CallerRateLimit";

    /// <summary>
    /// The dependency-injection key of the budget spent by RFC 7009 revocation requests.
    /// </summary>
    public const string Revocation = "Abblix.Oidc.Server.Revocation.CallerRateLimit";

    /// <summary>
    /// Builds the limiter a single endpoint spends, giving every client identifier its own fixed window.
    /// </summary>
    /// <param name="options">The budget one client gets within one window.</param>
    /// <returns>
    /// A limiter that refuses once a client is over its budget, or one that permits everything when
    /// <see cref="CallerRateLimitOptions.PermitLimit"/> is null.
    /// </returns>
    /// <remarks>
    /// Nothing is queued: a caller over its budget is told so immediately with a <c>Retry-After</c>, because the
    /// alternative is holding its request open and spending this server's own capacity on the client that is
    /// already using too much of it.
    /// </remarks>
    internal static PartitionedRateLimiter<string> Create(CallerRateLimitOptions options)
        => PartitionedRateLimiter.Create<string, string>(
            clientId => options.PermitLimit is { } permitLimit
                ? RateLimitPartition.GetFixedWindowLimiter(
                    clientId,
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = permitLimit,
                        Window = options.Window,
                        QueueLimit = 0,
                        AutoReplenishment = true,
                    })
                : RateLimitPartition.GetNoLimiter(clientId));
}
