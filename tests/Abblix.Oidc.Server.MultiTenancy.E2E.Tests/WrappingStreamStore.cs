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
/// A store a host wraps around its stream store, as one adding logging or metrics does, passing every call on and
/// keeping no partitions of its own.
/// </summary>
/// <param name="inner">The store wrapped.</param>
internal sealed class WrappingStreamStore(IStreamStore inner) : IStreamStore
{
    /// <inheritdoc />
    public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => inner.TryCreateAsync(stream, cancellationToken);

    /// <inheritdoc />
    public Task<StreamState?> FindAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => inner.FindAsync(receiverId, streamId, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAsync(string receiverId, CancellationToken cancellationToken = default)
        => inner.ListAsync(receiverId, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
        => inner.ListAllAsync(cancellationToken);

    /// <inheritdoc />
    public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => inner.UpdateAsync(stream, cancellationToken);

    /// <inheritdoc />
    public Task<bool> DeleteAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => inner.DeleteAsync(receiverId, streamId, cancellationToken);
}
