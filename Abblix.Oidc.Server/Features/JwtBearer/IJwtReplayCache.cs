// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
