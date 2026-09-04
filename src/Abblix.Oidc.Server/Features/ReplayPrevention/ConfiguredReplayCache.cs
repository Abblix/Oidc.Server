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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

/// <summary>
/// The server's replay cache: the storage primitive from Abblix.JWT wearing this deployment's
/// policy - the configured clock skew on top of every retention window, and the two log events
/// an operator's runbook keys off.
/// </summary>
/// <remarks>
/// The retention is the WIDEST window in which the thing an entry names could still be accepted:
/// what the deployment configured, or - where it configured nothing - the tolerance a client held to
/// no bounding profile receives. An entry must outlive that window, because a reservation that
/// expires first is a replay hole rather than a tidy cache.
///
/// It deliberately does not read a security profile. Nothing here knows which client a reservation
/// belongs to, and a profile is a property of the client: one that opted out of a bounding profile
/// is accepted for longer than the deployment's own profile would suggest, so retaining for the
/// deployment's window would leave exactly that client replayable in the gap. Over-retention costs
/// an entry held a while longer and cannot be a hole.
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
        // The WIDEST window any caller could still be accepted in, which is the LARGER of the two
        // answers rather than whichever one happens to be set. The two are reached by different
        // paths: the bearer grant honours this deployment's own setting, while a client assertion
        // is accepted on the profile's window and never reads that setting at all. Taking the
        // setting when it exists would therefore retain for thirty seconds what the assertion path
        // goes on accepting for minutes, and the assertion stays replayable in the gap.
        //
        // Under-retention is a replay hole; over-retention costs an entry held a while longer. That
        // asymmetry is why this takes the maximum rather than reading a profile it has no client to
        // look up. The configured value is deliberately not bounded here for the same reason: a
        // ceiling would only shorten the window.
        var unprofiled = SecurityProfileRequirements.Resolve(ClientSecurityProfile.None);
        var configured = options.CurrentValue.JwtBearer.ClockSkew ?? TimeSpan.Zero;
        var widest = configured < unprofiled.DefaultClockSkew.Past
            ? unprofiled.DefaultClockSkew.Past
            : configured;

        var skewed = expiresAt + widest;

        if (!await inner.TryReserveAsync(identifier, skewed, cancellationToken))
        {
            LogReplayDetected(identifier);
            return false;
        }

        LogMarkedAsUsed(identifier, skewed);
        return true;
    }
}
