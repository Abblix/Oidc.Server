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

using System.Collections.Concurrent;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The process-local stream store: right for a single-instance transmitter and for tests. A
/// scaled-out or restart-surviving transmitter registers a durable implementation of
/// <see cref="IStreamStore"/> instead - stream state is the contract between two parties, and
/// this store forgets it with the process.
/// </summary>
public sealed class InMemoryStreamStore : IStreamStore
{
    private readonly ConcurrentDictionary<(string ReceiverId, string StreamId), StreamState> _streams = new();

    /// <inheritdoc />
    public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        return Task.FromResult(_streams.TryAdd(KeyOf(stream), stream));
    }

    /// <inheritdoc />
    public Task<StreamState?> FindAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
        => Task.FromResult(_streams.GetValueOrDefault((receiverId, streamId)));

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAsync(
        string receiverId,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<StreamState>>(
            _streams.Values.Where(stream => stream.ReceiverId == receiverId).ToArray());

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<StreamState>>(_streams.Values.ToArray());

    /// <inheritdoc />
    public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        // A compare-and-swap loop rather than a bare indexer write: the indexer would CREATE a
        // stream that a concurrent delete just removed, resurrecting it silently.
        while (_streams.TryGetValue(KeyOf(stream), out var existing))
        {
            if (_streams.TryUpdate(KeyOf(stream), stream, existing))
            {
                return Task.FromResult(true);
            }
        }

        return Task.FromResult(false);
    }

    /// <inheritdoc />
    public Task<bool> DeleteAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
        => Task.FromResult(_streams.TryRemove((receiverId, streamId), out _));

    private static (string, string) KeyOf(StreamState stream) => (stream.ReceiverId, stream.StreamId);
}
