// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Features.JwtBearer;

/// <summary>
/// Legacy two-step replay-cache contract: a separate <see cref="IsReplayedAsync"/>
/// read followed by a <see cref="MarkAsUsedAsync"/> write. The shape leaks a
/// read-then-write race window to concurrent presenters of the same jti.
/// </summary>
/// <remarks>
/// Replaced by <see cref="ReplayPrevention.IJwtReplayCache.TryAddAsync"/>, whose
/// single-call shape lets atomic-capable backends close the race natively. This
/// interface remains as a backward-compat alias so host code that DI-resolves the
/// legacy type still receives a working instance during the transition window.
/// </remarks>
[Obsolete($"Use {nameof(Features)}.{nameof(ReplayPrevention)}.{nameof(IJwtReplayCache)}." +
          $"{nameof(ReplayPrevention.IJwtReplayCache.TryAddAsync)}. The single-call shape " +
          "lets atomic backends close the read-then-write race the legacy two-step contract leaks.")]
[SuppressMessage("Major Code Smell", "S1133:Deprecated code should be removed",
    Justification = "Permanent backward-compat shim; removal is a major-version concern.")]
public interface IJwtReplayCache
{
    /// <summary>
    /// Checks if a JWT with the specified JTI has already been used.
    /// </summary>
    /// <param name="jti">The JWT ID (jti claim) to check.</param>
    /// <returns>
    /// A task that completes with true if the JWT has already been used (replay detected);
    /// false if this is the first time the JWT is being presented.
    /// </returns>
    Task<bool> IsReplayedAsync(string jti);

    /// <summary>
    /// Marks a JWT as used by storing its JTI in the cache until the specified expiration time.
    /// </summary>
    /// <param name="jti">The JWT ID (jti claim) to mark as used.</param>
    /// <param name="expiresAt">
    /// The time at which the JWT expires. The JTI will be stored until this time plus a small buffer.
    /// If null, a default expiration will be used.
    /// </param>
    /// <returns>A task that completes when the JTI has been stored.</returns>
    Task MarkAsUsedAsync(string jti, DateTimeOffset? expiresAt);
}
