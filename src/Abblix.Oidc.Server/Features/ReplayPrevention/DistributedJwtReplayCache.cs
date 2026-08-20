// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt.ReplayPrevention;

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

/// <summary>
/// The deprecated contract's default implementation, kept so a host that resolves
/// <see cref="IJwtReplayCache"/> still receives a working object. It stores nothing of its own:
/// every reservation goes to the same <see cref="IReplayCache"/> the server's own consumers use,
/// so the deprecated and current spellings share one set of entries and cannot disagree about
/// whether an identifier has been seen.
/// </summary>
/// <remarks>
/// The only behaviour left here is the one the current contract deliberately dropped: an absent
/// expiry. The moved contract requires its caller to say when an identifier stops being worth
/// remembering, because a cache that guesses either outlives or forgets the window its caller
/// actually validates against. This shim keeps guessing on its callers' behalf, with the hour the
/// deprecated contract has always used.
/// </remarks>
/// <param name="replayCache">Where the reservation lands.</param>
/// <param name="timeProvider">Turns an absent expiry into an absolute moment.</param>
[Obsolete($"Use {nameof(Abblix)}.{nameof(Jwt)}.{nameof(Jwt.ReplayPrevention)}." +
          $"{nameof(IReplayCache)}, registered by the same calls that used to register this type.")]
[SuppressMessage("Major Code Smell", "S1133:Deprecated code should be removed",
    Justification = "Backward-compat shim for hosts that resolve the deprecated contract; removal is a major-version concern.")]
public class DistributedJwtReplayCache(
    IReplayCache replayCache,
    TimeProvider timeProvider) : IJwtReplayCache
{
    /// <inheritdoc />
    public Task<bool> TryAddAsync(string jti, DateTimeOffset? expiresAt)
        => replayCache.TryReserveAsync(
            jti,
            expiresAt ?? timeProvider.GetUtcNow() + ConfiguredReplayCache.DefaultExpiration);
}
