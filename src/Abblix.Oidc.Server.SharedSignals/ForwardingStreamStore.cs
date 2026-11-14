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
/// A stream store passing every call to <paramref name="inner"/>, for a decorator overriding only the calls it
/// changes.
/// </summary>
/// <param name="inner">The store every call is passed to.</param>
internal abstract class ForwardingStreamStore(IStreamStore inner) : IStreamStore
{
    /// <summary>The store every call is passed to.</summary>
    protected IStreamStore Inner => inner;

    /// <inheritdoc />
    public virtual Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
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
    public virtual Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => inner.UpdateAsync(stream, cancellationToken);

    /// <inheritdoc />
    public virtual Task<bool> DeleteAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => inner.DeleteAsync(receiverId, streamId, cancellationToken);
}
