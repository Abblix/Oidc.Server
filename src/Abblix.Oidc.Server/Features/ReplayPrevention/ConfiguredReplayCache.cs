// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

/// <summary>
/// The server's replay cache: the storage primitive from Abblix.JWT wearing this deployment's
/// policy - the configured clock skew on top of every retention window, and the two log events
/// an operator's runbook keys off.
/// </summary>
/// <remarks>
/// The skew is read from <see cref="JwtBearerOptions.ClockSkew"/> and applied to every consumer,
/// DPoP proofs included. That is deliberate rather than tidy: one knob decides how far this
/// server's notion of "expired" may lag a presenter's, and splitting it per profile would let a
/// deployment tighten one path while believing it had tightened all of them.
/// </remarks>
/// <param name="logger">Records the two replay events.</param>
/// <param name="inner">The storage the reservation actually lands in.</param>
/// <param name="options">Where the clock skew is read from, re-read per call so a live
/// configuration change takes effect without a restart.</param>
internal sealed partial class ConfiguredReplayCache(
    ILogger<ConfiguredReplayCache> logger,
    IReplayCache inner,
    IOptionsMonitor<OidcOptions> options) : IReplayCache
{
    /// <summary>
    /// How long an identifier is remembered when its token names no expiry. RFC 7523 Section 3
    /// makes "exp" REQUIRED in an assertion, so this is the fallback for a token that arrived
    /// without one rather than a window anything is designed around.
    /// </summary>
    internal static readonly TimeSpan DefaultExpiration = TimeSpan.FromHours(1);

    /// <inheritdoc />
    public async Task<bool> TryReserveAsync(
        string identifier,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        var skewed = expiresAt + options.CurrentValue.JwtBearer.ResolveClockSkew(
            options.CurrentValue.DefaultSecurityProfile);

        if (!await inner.TryReserveAsync(identifier, skewed, cancellationToken))
        {
            LogReplayDetected(identifier);
            return false;
        }

        LogMarkedAsUsed(identifier, skewed);
        return true;
    }
}
