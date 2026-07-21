// Abblix OIDC Client Library
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

using System.Collections.Concurrent;

namespace Abblix.Oidc.Client.Features.BackChannelLogout;

/// <summary>
/// Remembers seen Logout Tokens in this process.
/// </summary>
/// <remarks>
/// Enough for an application that runs as one instance, and the default because a guard that has to be
/// configured before it works is one that is usually not working. It is not enough behind a load balancer:
/// a replay sent to a second instance meets a memory that never saw the original. A host running more than
/// one instance registers a guard backed by whatever its instances share, and the interface exists so that
/// this is a registration rather than a change here.
/// </remarks>
/// <param name="timeProvider">Reads the current time, so entries can be dropped once they cannot matter.</param>
public sealed class InMemoryLogoutTokenReplayGuard(TimeProvider timeProvider) : ILogoutTokenReplayGuard
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<bool> TryRecordAsync(
        string tokenId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();

        DropExpired(now);

        // One operation, so two concurrent posts of the same token cannot both find nothing recorded.
        var recorded = _seen.TryAdd(tokenId, expiresAt);

        // An entry left over from a token that has since expired is not a replay: the expiry check refuses
        // that token before this guard is reached, so the record says nothing about the token being offered
        // now. Treat it as absent and take its place.
        if (!recorded && _seen.TryGetValue(tokenId, out var previous) && previous <= now)
            recorded = _seen.TryUpdate(tokenId, expiresAt, previous);

        return Task.FromResult(recorded);
    }

    /// <summary>
    /// Forgets tokens that can no longer be replayed.
    /// </summary>
    /// <remarks>
    /// Swept on write rather than on a timer: the memory only grows when tokens arrive, so that is the only
    /// moment it needs shrinking, and a timer would keep a host awake to tidy a dictionary.
    /// </remarks>
    private void DropExpired(DateTimeOffset now)
    {
        foreach (var (tokenId, expiresAt) in _seen)
        {
            if (expiresAt <= now)
                _seen.TryRemove(new KeyValuePair<string, DateTimeOffset>(tokenId, expiresAt));
        }
    }
}
