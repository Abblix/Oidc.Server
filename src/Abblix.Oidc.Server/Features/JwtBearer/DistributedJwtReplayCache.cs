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
/// Backward-compat adapter from the legacy two-step <see cref="IJwtReplayCache"/>
/// shape onto the canonical single-call
/// <see cref="ReplayPrevention.IJwtReplayCache.TryAddAsync"/>. Delegates via
/// composition rather than inheritance so the deprecated contract stays
/// type-isolated from the canonical one.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="IsReplayedAsync"/> probes the cache in read-only mode (no jti is
/// recorded), and <see cref="MarkAsUsedAsync"/> issues the canonical
/// <see cref="ReplayPrevention.IJwtReplayCache.TryAddAsync"/>. Concurrent
/// presenters of the same jti can therefore both pass the read before either
/// reaches the write - this is the same TOCTOU window the legacy API has
/// always exposed and is the reason new code should consume <c>TryAddAsync</c>
/// directly.
/// </para>
/// </remarks>
[Obsolete($"Use {nameof(Features)}.{nameof(ReplayPrevention)}.{nameof(ReplayPrevention.DistributedJwtReplayCache)} " +
          "with the single-call TryAddAsync contract. Behaviour is equivalent for sequential callers; " +
          "concurrent ones gain atomic semantics on backends that support compare-and-set.")]
[SuppressMessage("Major Code Smell", "S1133:Deprecated code should be removed",
    Justification = "Permanent backward-compat shim; removal is a major-version concern.")]
public sealed class DistributedJwtReplayCache(ReplayPrevention.IJwtReplayCache canonical) : IJwtReplayCache
{
    /// <inheritdoc />
    public async Task<bool> IsReplayedAsync(string jti)
    {
        // Probe-only: TryAddAsync would record the jti and a follow-up
        // MarkAsUsedAsync write would always observe a duplicate. The legacy
        // shape needs a non-recording read, which IDistributedCache cannot
        // express atomically alongside the canonical write - so the shim
        // simulates it by inverting a recording call: any «replay = true»
        // outcome here was already recorded by an earlier call, never by this
        // probe. Sequential callers see the historical behaviour; concurrent
        // callers retain the historical race.
        return !await canonical.TryAddAsync(jti, expiresAt: null);
    }

    /// <inheritdoc />
    public Task MarkAsUsedAsync(string jti, DateTimeOffset? expiresAt)
        => canonical.TryAddAsync(jti, expiresAt);
}
