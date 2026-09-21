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
/// The budgets this server spends, kept as <see cref="PartitionedRateLimiter{TResource}"/> instances registered
/// under the keys below. Each key says what its budget is partitioned by, because that is what decides who a
/// refusal reaches.
/// </summary>
/// <remarks>
/// The type is the one from <c>System.Threading.RateLimiting</c> rather than an interface of ours, so a host that
/// needs a different policy - a token bucket, a sliding window, a limiter that counts across several nodes -
/// registers the platform's own abstraction under the same key and this server spends that budget instead. ASP.NET
/// Core's rate-limiting middleware cannot serve here: it runs before the request reaches the endpoint, where the
/// caller is still whoever holds the socket, and the whole point of this budget is that it is charged to the
/// client the request authenticated as.
/// <para>
/// A budget is taken with a single attempt that never waits, and held for as long as the request is being
/// validated - which covers reading the token and stops there, before the endpoint's processor writes anything.
/// So a limiter counting requests in flight bounds the signature verification rather than only the count, and a
/// deployment that needs the work after validation bounded too wraps the endpoint's handler itself. A limiter
/// configured to queue does not queue here either: a caller it would have held is refused instead, because an
/// endpoint holding a request open is what this feature exists to stop.
/// </para>
/// </remarks>
public static class CallerRateLimiters
{
    /// <summary>
    /// The dependency-injection key of the budget spent by RFC 7662 introspection requests, partitioned by the
    /// identifier of the client that authenticated.
    /// </summary>
    public const string Introspection = "Abblix.Oidc.Server.Introspection.CallerRateLimit";

    /// <summary>
    /// The dependency-injection key of the budget spent by RFC 7009 revocation requests, partitioned by the
    /// identifier of the client that authenticated - and, for a public client, by that identifier together with
    /// the address the request came from, since the identifier alone is not that client's own.
    /// </summary>
    public const string Revocation = "Abblix.Oidc.Server.Revocation.CallerRateLimit";

    /// <summary>
    /// The dependency-injection key of the budget of failed client authentications one source address gets,
    /// partitioned by that address. Every endpoint that authenticates a client spends the same one, because a
    /// sender hammering any of them is the same sender, and the budget is about the sender rather than about
    /// what it asked for.
    /// </summary>
    public const string AuthenticationFailures = "Abblix.Oidc.Server.AuthenticationFailures.RateLimit";

    /// <summary>
    /// Builds the limiter a single endpoint spends, giving every client identifier its own fixed window.
    /// </summary>
    /// <param name="options">The budget one client gets within one window.</param>
    /// <returns>
    /// A limiter that refuses once a client is over its budget, or one that permits everything when
    /// <see cref="CallerRateLimitOptions.PermitLimit"/> is null.
    /// </returns>
    /// <remarks>
    /// Its queue is empty by construction, for the reason stated on the type: a caller over its budget is told
    /// so immediately with a <c>Retry-After</c>, rather than held open at the expense of the server it is
    /// already asking too much of.
    /// </remarks>
    internal static PartitionedRateLimiter<string> Create(CallerRateLimitOptions options)
        => Create(options.PermitLimit, options.Window);

    /// <summary>
    /// Builds the limiter both endpoints spend for failed client authentications, giving every source address
    /// its own fixed window.
    /// </summary>
    /// <param name="options">The failures one address gets within one window.</param>
    /// <returns>
    /// A limiter that refuses once an address is over its budget, or one that permits everything when
    /// <see cref="AuthenticationFailureLimitOptions.PermitLimit"/> is null.
    /// </returns>
    internal static PartitionedRateLimiter<string> Create(AuthenticationFailureLimitOptions options)
        => Create(options.PermitLimit, options.Window);

    private static PartitionedRateLimiter<string> Create(int? permitLimit, TimeSpan window)
        => PartitionedRateLimiter.Create<string, string>(
            key => permitLimit is { } limit
                ? RateLimitPartition.GetFixedWindowLimiter(
                    key,
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = limit,
                        Window = window,
                        QueueLimit = 0,
                        AutoReplenishment = true,
                    })
                : RateLimitPartition.GetNoLimiter(key));
}
