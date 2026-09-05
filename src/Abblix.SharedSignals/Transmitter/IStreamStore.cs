// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Where a transmitter keeps its streams. The contract is deliberately a plain keyed store over
/// immutable snapshots: the Management API owns the SSF semantics, the store owns nothing but
/// persistence, and a durable implementation - a database in the host application - replaces
/// the in-memory one without either side changing.
/// </summary>
public interface IStreamStore
{
    /// <summary>
    /// Stores a new stream.
    /// </summary>
    /// <param name="stream">The stream's initial state.</param>
    /// <param name="cancellationToken">Cancels I/O a durable implementation performs.</param>
    /// <returns>True when stored; false when a stream with the same receiver and identifier
    /// already exists.</returns>
    Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds one stream of one receiver.
    /// </summary>
    /// <param name="receiverId">The receiver the stream belongs to.</param>
    /// <param name="streamId">The stream's identifier.</param>
    /// <param name="cancellationToken">Cancels I/O a durable implementation performs.</param>
    /// <returns>The stream's state, or null when no such stream exists for this receiver.
    /// </returns>
    Task<StreamState?> FindAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the streams of one receiver, for the list form of the configuration read
    /// (SSF 1.0 Section 8.1.1.2). An empty list is a receiver with no streams, never an error.
    /// </summary>
    /// <param name="receiverId">The receiver whose streams are listed.</param>
    /// <param name="cancellationToken">Cancels I/O a durable implementation performs.</param>
    Task<IReadOnlyList<StreamState>> ListAsync(
        string receiverId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists every stream of every receiver - the dispatcher's view, since an event is matched
    /// against all streams at once.
    /// </summary>
    /// <param name="cancellationToken">Cancels I/O a durable implementation performs.</param>
    Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Replaces a stream's state with a new snapshot, keyed by its receiver and identifier.
    /// </summary>
    /// <param name="stream">The new state.</param>
    /// <param name="cancellationToken">Cancels I/O a durable implementation performs.</param>
    /// <returns>True when replaced; false when no such stream exists to replace.</returns>
    Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a stream (SSF 1.0 Section 8.1.1.5).
    /// </summary>
    /// <param name="receiverId">The receiver the stream belongs to.</param>
    /// <param name="streamId">The stream's identifier.</param>
    /// <param name="cancellationToken">Cancels I/O a durable implementation performs.</param>
    /// <returns>True when deleted; false when no such stream existed.</returns>
    Task<bool> DeleteAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default);
}
