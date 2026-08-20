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
