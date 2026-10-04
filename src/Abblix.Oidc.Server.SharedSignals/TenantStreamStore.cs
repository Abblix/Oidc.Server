// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Keeps each tenant's streams apart in a store shared by every tenant.
/// </summary>
/// <remarks>
/// A stream is stored under its receiver's identifier prefixed with the tenant's space, which names the tenant and
/// its generation, and handed back without it. So one tenant's receiver never finds another's stream, a listing
/// returns only the current tenant's streams, and a tenant created again under the identifier of one removed takes
/// over none of them.
/// </remarks>
/// <param name="inner">The store every tenant shares.</param>
/// <param name="tenantAccessor">Names the tenant of the current request or scope.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantStreamStore(IStreamStore inner, ITenantAccessor tenantAccessor) : IStreamStore
{
    /// <inheritdoc />
    public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => inner.TryCreateAsync(Owned(stream), cancellationToken);

    /// <inheritdoc />
    public async Task<StreamState?> FindAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
        => await inner.FindAsync(Own(receiverId), streamId, cancellationToken) is { } stored
            ? Unowned(stored)
            : null;

    /// <inheritdoc />
    public async Task<IReadOnlyList<StreamState>> ListAsync(
        string receiverId,
        CancellationToken cancellationToken = default)
        => [.. (await inner.ListAsync(Own(receiverId), cancellationToken)).Select(Unowned)];

    /// <inheritdoc />
    public async Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
    {
        var space = Own(string.Empty);
        return
        [
            .. (await inner.ListAllAsync(cancellationToken))
                .Where(stream => stream.ReceiverId.StartsWith(space, StringComparison.Ordinal))
                .Select(stream => stream with { ReceiverId = stream.ReceiverId[space.Length..] }),
        ];
    }

    /// <inheritdoc />
    public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => inner.UpdateAsync(Owned(stream), cancellationToken);

    /// <inheritdoc />
    public Task<bool> DeleteAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => inner.DeleteAsync(Own(receiverId), streamId, cancellationToken);

    private string Own(string receiverId) => TenantKey.Of(tenantAccessor, receiverId);

    private StreamState Owned(StreamState stream) => stream with { ReceiverId = Own(stream.ReceiverId) };

    private StreamState Unowned(StreamState stream)
        => stream with { ReceiverId = stream.ReceiverId[Own(string.Empty).Length..] };
}
