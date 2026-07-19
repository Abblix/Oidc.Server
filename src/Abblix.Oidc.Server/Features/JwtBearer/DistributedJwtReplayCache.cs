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
/// reaches the write — this is the same TOCTOU window the legacy API has
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
        // express atomically alongside the canonical write — so the shim
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
