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
/// A caller budget is keyed by a pair rather than by the two halves joined into one string, because nothing
/// constrains the characters in a client identifier and a registration could otherwise take a name spelled
/// like another caller's key.
/// <para>
/// The type is the platform's rather than an interface of ours, so a host registers its own policy under the
/// same key. ASP.NET Core's rate-limiting middleware cannot serve here: it runs before the request reaches the
/// endpoint, where the caller is still whoever holds the socket.
/// </para>
/// <para>
/// A budget is taken with a single attempt that never waits and held until validation ends, so a limiter
/// counting requests in flight bounds the signature verification rather than only the count. A caller a
/// queueing limiter would have held is refused instead.
/// </para>
/// </remarks>
public static class CallerRateLimiters
{
    /// <summary>
    /// The dependency-injection key of the budget spent by RFC 7662 introspection requests, partitioned by the
    /// identifier of the client that authenticated. The endpoint admits no public client, so the source half of
    /// the key is never set here.
    /// </summary>
    public const string Introspection = "Abblix.Oidc.Server.Introspection.CallerRateLimit";

    /// <summary>
    /// The dependency-injection key of the budget spent by RFC 7009 revocation requests, partitioned by the
    /// identifier of the client that authenticated - and, for a public client, by that identifier paired with
    /// the address the request came from, since the identifier alone is not that client's own.
    /// </summary>
    public const string Revocation = "Abblix.Oidc.Server.Revocation.CallerRateLimit";

    /// <summary>
    /// The dependency-injection key of the budget of failed client authentications one source address gets,
    /// partitioned by that address and spent by every endpoint that authenticates a client, since a sender
    /// hammering any of them is the same sender.
    /// </summary>
    public const string AuthenticationFailures = "Abblix.Oidc.Server.AuthenticationFailures.RateLimit";

    /// <summary>
    /// Builds the limiter a single endpoint spends, giving every caller its own fixed window.
    /// </summary>
    /// <param name="options">The budget one caller gets within one window.</param>
    /// <returns>
    /// A limiter that refuses once a caller is over its budget, or one that permits everything when
    /// <see cref="CallerRateLimitOptions.PermitLimit"/> is null.
    /// </returns>
    internal static PartitionedRateLimiter<(string ClientId, string? Source)> Create(CallerRateLimitOptions options)
        => Create<(string, string?)>(options.PermitLimit, options.Window);

    /// <summary>
    /// Builds the limiter every endpoint that authenticates a client spends for failed client authentications,
    /// giving every source address its own fixed window.
    /// </summary>
    /// <param name="options">The failures one address gets within one window.</param>
    /// <returns>
    /// A limiter that refuses once an address is over its budget, or one that permits everything when
    /// <see cref="AuthenticationFailureLimitOptions.PermitLimit"/> is null.
    /// </returns>
    internal static PartitionedRateLimiter<string> Create(AuthenticationFailureLimitOptions options)
        => Create<string>(options.PermitLimit, options.Window);

    private static PartitionedRateLimiter<TKey> Create<TKey>(int? permitLimit, TimeSpan window) where TKey : notnull
        => PartitionedRateLimiter.Create<TKey, TKey>(
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
