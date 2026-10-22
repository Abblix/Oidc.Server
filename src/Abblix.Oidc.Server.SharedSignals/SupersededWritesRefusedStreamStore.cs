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
/// The backing store of one tenant's store of declared streams, refusing every write once another store has replaced
/// it, so a reconcile it started before the tenant moved cannot write the issuer the tenant left after its
/// replacement wrote the new one.
/// </summary>
/// <remarks>
/// A refused write answers as one the store did not take, which the store of declared streams retries and gives up
/// on, and a caller writing through the replaced store at the moment of the move retries. A write that passed the
/// check before the replacement either loses to the replacement's write on the stream's version or is written over
/// by it.
/// </remarks>
/// <param name="inner">The tenant's part of the store.</param>
/// <param name="installed">Whether the store this backs is still the one the tenant is served.</param>
internal sealed class SupersededWritesRefusedStreamStore(IStreamStore inner, Func<bool> installed)
    : ForwardingStreamStore(inner)
{
    /// <inheritdoc />
    public override Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => installed() ? Inner.TryCreateAsync(stream, cancellationToken) : Task.FromResult(false);

    /// <inheritdoc />
    public override Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => installed() ? Inner.UpdateAsync(stream, cancellationToken) : Task.FromResult(false);

    /// <inheritdoc />
    public override Task<bool> DeleteAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => installed() ? Inner.DeleteAsync(receiverId, streamId, cancellationToken) : Task.FromResult(false);
}
