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
/// A refused write answers as one the store did not take: the store of declared streams retries it and gives up,
/// and a receiver's write that went through the replaced store is sent once more through the store the tenant is
/// served now (<see cref="TenantConfiguredStreamStore"/>).
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
