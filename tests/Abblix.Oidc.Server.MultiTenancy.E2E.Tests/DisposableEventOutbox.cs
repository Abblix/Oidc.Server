// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// An outbox in memory that records whether whoever built it has disposed it.
/// </summary>
internal sealed class DisposableEventOutbox : IEventOutbox, IDisposable
{
    private readonly InMemoryEventOutbox _inner = new();

    /// <summary>
    /// Whether the outbox has been disposed.
    /// </summary>
    public bool Disposed { get; private set; }

    /// <inheritdoc />
    public Task EnqueueAsync(
        string receiverId,
        string streamId,
        OutboxItem item,
        CancellationToken cancellationToken = default)
        => _inner.EnqueueAsync(receiverId, streamId, item, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<OutboxItem>> PendingAsync(
        string receiverId,
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default)
        => _inner.PendingAsync(receiverId, streamId, maxCount, cancellationToken);

    /// <inheritdoc />
    public Task AcknowledgeAsync(
        string receiverId,
        string streamId,
        IReadOnlyCollection<string> jwtIds,
        CancellationToken cancellationToken = default)
        => _inner.AcknowledgeAsync(receiverId, streamId, jwtIds, cancellationToken);

    /// <inheritdoc />
    public Task ClearAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => _inner.ClearAsync(receiverId, streamId, cancellationToken);

    /// <inheritdoc />
    public void Dispose() => Disposed = true;
}
