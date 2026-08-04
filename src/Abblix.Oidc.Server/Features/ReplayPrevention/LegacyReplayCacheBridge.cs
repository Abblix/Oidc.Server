// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
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
using Abblix.Jwt.ReplayPrevention;

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

/// <summary>
/// Routes the server's reservations into a host's own implementation of the deprecated contract.
/// </summary>
/// <remarks>
/// A host that replaced <see cref="IJwtReplayCache"/> did so to decide where replay state lives -
/// a strictly atomic backend, most often. Once the server's own consumers moved to
/// <see cref="IReplayCache"/>, that decision would have stopped taking effect while the
/// registration still looked healthy, which is the worst way for a security control to lapse.
/// This bridge is registered in exactly that case, so the host stays in charge until it migrates.
/// </remarks>
/// <param name="legacy">The host's implementation of the deprecated contract.</param>
[SuppressMessage("Major Code Smell", "S1133:Deprecated code should be removed",
    Justification = "Bridges a deprecated contract a host may still implement; removal is a major-version concern.")]
internal sealed class LegacyReplayCacheBridge(
#pragma warning disable CS0618 // the deprecated contract is this type's whole reason to exist
    IJwtReplayCache legacy)
#pragma warning restore CS0618
    : IReplayCache
{
    /// <inheritdoc />
    public Task<bool> TryReserveAsync(
        string identifier,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
        => legacy.TryAddAsync(identifier, expiresAt);
}
