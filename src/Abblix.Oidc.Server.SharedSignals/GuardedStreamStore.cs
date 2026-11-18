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
/// A tenant's stream store that refuses every call made where its tenant is not served.
/// </summary>
/// <param name="inner">The tenant's part of the store.</param>
/// <param name="guard">Refuses a call made where the tenant is not served.</param>
internal sealed class GuardedStreamStore(IStreamStore inner, TenantPartGuard guard) : IStreamStore
{
    /// <inheritdoc />
    public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        guard.EnsureServed();
        return inner.TryCreateAsync(stream, cancellationToken);
    }

    /// <inheritdoc />
    public Task<StreamState?> FindAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
    {
        guard.EnsureServed();
        return inner.FindAsync(receiverId, streamId, cancellationToken);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAsync(string receiverId, CancellationToken cancellationToken = default)
    {
        guard.EnsureServed();
        return inner.ListAsync(receiverId, cancellationToken);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
    {
        guard.EnsureServed();
        return inner.ListAllAsync(cancellationToken);
    }

    /// <inheritdoc />
    public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        guard.EnsureServed();
        return inner.UpdateAsync(stream, cancellationToken);
    }

    /// <inheritdoc />
    public Task<bool> DeleteAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
    {
        guard.EnsureServed();
        return inner.DeleteAsync(receiverId, streamId, cancellationToken);
    }
}
