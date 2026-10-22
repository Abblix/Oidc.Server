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
/// A tenant's part of the stream store that deletes a stream it created once the creation of the tenant it belongs to
/// turns out to be released.
/// </summary>
/// <remarks>
/// The release is canceled before the tenant's streams are listed and deleted, so a create the store acknowledged
/// before the cancel is in that listing, and one acknowledged after it is removed here; no lock is held across the
/// store's calls. This holds for a store whose listing returns every write it has acknowledged.
/// </remarks>
/// <param name="inner">The tenant's part of the store.</param>
/// <param name="released">Canceled once the creation of the tenant is released.</param>
internal sealed class ReleaseCheckingStreamStore(IStreamStore inner, CancellationToken released) : IStreamStore
{
    /// <inheritdoc />
    public async Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        var created = await inner.TryCreateAsync(stream, cancellationToken);

        // Deleted whatever the caller's token says: a caller giving up must not leave the stream for nobody to delete
        if (created && released.IsCancellationRequested)
            await inner.DeleteAsync(stream.ReceiverId, stream.Configuration.StreamId, CancellationToken.None);

        return created;
    }

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
