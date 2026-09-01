// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Where minted SETs wait for delivery, one queue per stream. The queue IS the holding the
/// status rules speak of: a paused stream's events stay here because nothing drains them
/// (SSF 1.0 Section 8.1.2.1), a poll delivery reads and re-reads here until acknowledged
/// (RFC 8936 Section 2.4), and a push delivery removes an item only once the receiver's 202
/// earned it. Order is enqueue order, which is what keeps same-principal events in generation
/// order across a pause.
/// </summary>
public interface IEventOutbox
{
    /// <summary>
    /// Appends a SET to a stream's queue.
    /// </summary>
    /// <param name="streamId">The stream the SET was minted for.</param>
    /// <param name="item">The minted SET.</param>
    /// <param name="cancellationToken">Cancels I/O a durable implementation performs.</param>
    Task EnqueueAsync(string streamId, OutboxItem item, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads the unacknowledged head of a stream's queue, oldest first, without removing
    /// anything - redelivery of the unacknowledged is the delivery protocols' own semantics.
    /// </summary>
    /// <param name="streamId">The stream whose queue is read.</param>
    /// <param name="maxCount">
    /// The most items to return; null returns everything pending, mirroring an absent
    /// "maxEvents" (RFC 8936 Section 2.2).</param>
    /// <param name="cancellationToken">Cancels I/O a durable implementation performs.</param>
    Task<IReadOnlyList<OutboxItem>> PendingAsync(
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes acknowledged SETs from a stream's queue, releasing the transmitter from
    /// retaining them (RFC 8936 Section 2.2). Identifiers with nothing to match are ignored -
    /// an acknowledgement can only arrive for something that was once here.
    /// </summary>
    /// <param name="streamId">The stream whose queue is acknowledged.</param>
    /// <param name="jwtIds">The "jti" values being acknowledged.</param>
    /// <param name="cancellationToken">Cancels I/O a durable implementation performs.</param>
    Task AcknowledgeAsync(
        string streamId,
        IReadOnlyCollection<string> jwtIds,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Drops a stream's whole queue - the companion of deleting or disabling the stream, whose
    /// events are not held for later (SSF 1.0 Sections 8.1.1.5, 8.1.2.1).
    /// </summary>
    /// <param name="streamId">The stream whose queue is dropped.</param>
    /// <param name="cancellationToken">Cancels I/O a durable implementation performs.</param>
    Task ClearAsync(string streamId, CancellationToken cancellationToken = default);
}
