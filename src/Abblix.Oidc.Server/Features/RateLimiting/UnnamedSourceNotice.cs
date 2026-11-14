// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.RateLimiting;

/// <summary>
/// Says, once per budget, that a budget counted per address is on and a request arrived from no address
/// this server can name, which that budget does not charge.
/// </summary>
/// <remarks>
/// Leaving such a request uncharged is deliberate: nothing shared stands behind these budgets for it to
/// spend, and charging every such request under one name would let one sender refuse everybody else who
/// arrives the same way - on a deployment served over a unix socket, every caller. What is not acceptable is
/// that a limit an operator turned on then refuses those requests without a word. The usual cause is a
/// proxy that reaches the server over a unix socket: a proxy connecting over TCP gives its own address,
/// which is a different problem, one address shared by every caller.
/// <para>
/// Once per instance, and a server holds one: the container registers it as a singleton.
/// </para>
/// <para>
/// Whether a budget is on is read from the settings. A host that registered a limiter of its own under a
/// budget's key while the settings leave the budget off is not told, although requests with no address
/// never reach its limiter either.
/// </para>
/// </remarks>
public sealed partial class UnnamedSourceNotice(ILogger<UnnamedSourceNotice> logger, IOptions<OidcOptions> options)
{
    private readonly ConcurrentDictionary<string, bool> _reported = new(StringComparer.Ordinal);

    /// <summary>
    /// Reports that <paramref name="budget"/> could not charge a request, the first time it happens on this
    /// server and only while that budget is on.
    /// </summary>
    /// <param name="budget">The key of a budget counted per address, one of <see cref="CallerRateLimiters"/>.</param>
    public void Report(string budget)
    {
        var (isOn, uncharged) = Describe(budget);
        if (isOn && _reported.TryAdd(budget, true))
            LogBudgetLeavesUncharged(budget, uncharged);
    }

    /// <summary>
    /// Whether the budget is on, and which of its requests go uncharged without an address - for revocation
    /// only a public client's, since a confidential client is charged by its identifier alone.
    /// </summary>
    private (bool IsOn, string Uncharged) Describe(string budget) => budget switch
    {
        CallerRateLimiters.AuthenticationFailures => (
            options.Value.AuthenticationFailureLimit.PermitLimit is not null,
            "failed client authentications"),
        CallerRateLimiters.Revocation => (
            options.Value.CallerRateLimit.PermitLimit is not null,
            "revocation requests from public clients"),
        _ => throw new ArgumentOutOfRangeException(
            nameof(budget), budget, "No budget of this name is counted per address"),
    };
}
