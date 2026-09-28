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
/// this server can name, which that budget does not count.
/// </summary>
/// <remarks>
/// Leaving such a request uncounted is deliberate: nothing shared stands behind these budgets for it to
/// spend, and counting every such request under one name would let one sender refuse everybody else who
/// arrives the same way - on a deployment behind a unix socket, every caller. What is not acceptable is
/// that a limit an operator turned on then refuses nobody without a word. The usual cause is a proxy whose
/// forwarded headers the host never resolved into the connection's address.
/// <para>
/// Whether a budget is on is read from the settings. A host that registered a limiter of its own under a
/// budget's key has chosen how that budget partitions, and is not told.
/// </para>
/// </remarks>
public sealed partial class UnnamedSourceNotice(ILogger<UnnamedSourceNotice> logger, IOptions<OidcOptions> options)
{
    private readonly ConcurrentDictionary<string, bool> _reported = new(StringComparer.Ordinal);

    /// <summary>
    /// Reports that <paramref name="budget"/> could not count a request, the first time it happens in this
    /// process and only while that budget is on.
    /// </summary>
    /// <param name="budget">The key of a budget counted per address, one of <see cref="CallerRateLimiters"/>.</param>
    public void Report(string budget)
    {
        if (IsOn(budget) && _reported.TryAdd(budget, true))
            LogBudgetCountsNothing(budget);
    }

    private bool IsOn(string budget) => budget switch
    {
        CallerRateLimiters.AuthenticationFailures => options.Value.AuthenticationFailureLimit.PermitLimit is not null,
        CallerRateLimiters.Revocation => options.Value.CallerRateLimit.PermitLimit is not null,
        _ => throw new ArgumentOutOfRangeException(
            nameof(budget), budget, "No budget of this name is counted per address"),
    };
}
