// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A stream store in memory that keeps each partition's streams in a store of its own, as a durable store keeping
/// partitions does on keys of their own.
/// </summary>
internal sealed class PartitionedMemoryStreamStore : IPartitionedStreamStore
{
    private readonly InMemoryStreamStore _own = new();
    private readonly ConcurrentDictionary<string, InMemoryStreamStore> _partitions = new(StringComparer.Ordinal);

    /// <summary>
    /// The store of each partition asked for, by its name.
    /// </summary>
    public IReadOnlyDictionary<string, InMemoryStreamStore> Partitions => _partitions;

    /// <inheritdoc />
    public IStreamStore Partition(string partition) => _partitions.GetOrAdd(partition, _ => new InMemoryStreamStore());

    /// <inheritdoc />
    public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => _own.TryCreateAsync(stream, cancellationToken);

    /// <inheritdoc />
    public Task<StreamState?> FindAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => _own.FindAsync(receiverId, streamId, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAsync(string receiverId, CancellationToken cancellationToken = default)
        => _own.ListAsync(receiverId, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
        => _own.ListAllAsync(cancellationToken);

    /// <inheritdoc />
    public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => _own.UpdateAsync(stream, cancellationToken);

    /// <inheritdoc />
    public Task<bool> DeleteAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => _own.DeleteAsync(receiverId, streamId, cancellationToken);
}
