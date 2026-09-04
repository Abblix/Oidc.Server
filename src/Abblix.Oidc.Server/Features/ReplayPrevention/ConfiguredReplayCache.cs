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
        // The WIDEST window any client could be accepted in, not the one the deployment's own
        // profile supplies. A client may carry a profile of its own, and a client that opted out
        // of a bounding one is accepted for longer than the deployment would be - so retaining for
        // the deployment's window would let that client's assertion be replayed in the gap between
        // the two. Under-retention is a replay hole; over-retention costs an entry held a while
        // longer, which is why the asymmetry is resolved this way rather than by reading a profile
        // this class has no client to look up.
        var unprofiled = SecurityProfileRequirements.Resolve(ClientSecurityProfile.None);
        var skewed = expiresAt + (options.CurrentValue.JwtBearer.ClockSkew
                                  ?? unprofiled.DefaultClockSkew.Past);

        if (!await inner.TryReserveAsync(identifier, skewed, cancellationToken))
        {
            LogReplayDetected(identifier);
            return false;
        }

        LogMarkedAsUsed(identifier, skewed);
        return true;
    }
}
