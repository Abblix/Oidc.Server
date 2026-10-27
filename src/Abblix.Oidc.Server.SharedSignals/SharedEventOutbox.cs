// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// The outbox the host registered, kept under a key of its own as the outbox every tenant shares, while the unkeyed
/// registration answers with the outbox of the tenant being served.
/// </summary>
/// <param name="inner">The outbox the host registered.</param>
internal sealed class SharedEventOutbox(IEventOutbox inner) : IEventOutbox
{
    /// <inheritdoc />
    public Task EnqueueAsync(
        string receiverId,
        string streamId,
        OutboxItem item,
        CancellationToken cancellationToken = default)
        => inner.EnqueueAsync(receiverId, streamId, item, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<OutboxItem>> PendingAsync(
        string receiverId,
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default)
        => inner.PendingAsync(receiverId, streamId, maxCount, cancellationToken);

    /// <inheritdoc />
    public Task AcknowledgeAsync(
        string receiverId,
        string streamId,
        IReadOnlyCollection<string> jwtIds,
        CancellationToken cancellationToken = default)
        => inner.AcknowledgeAsync(receiverId, streamId, jwtIds, cancellationToken);

    /// <inheritdoc />
    public Task ClearAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => inner.ClearAsync(receiverId, streamId, cancellationToken);
}
