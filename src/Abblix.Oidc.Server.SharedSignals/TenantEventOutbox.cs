// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Keeps each tenant's queued events apart in an outbox shared by every tenant.
/// </summary>
/// <remarks>
/// A queue is addressed by its receiver's identifier prefixed with the tenant's space, as
/// <see cref="TenantStreamStore"/> keeps the streams. Stream identifiers alone do not tell tenants apart: a stream a
/// tenant declares in configuration carries the identifier its operator chose, and two tenants may choose the same
/// one for the same receiver.
/// </remarks>
/// <param name="inner">The outbox every tenant shares.</param>
/// <param name="tenant">The tenant whose queues these are.</param>
/// <param name="guard">Refuses every call made while another tenant is served.</param>
internal sealed class TenantEventOutbox(IEventOutbox inner, TenantDefinition tenant, TenantPartGuard guard)
    : IEventOutbox
{
    /// <inheritdoc />
    public Task EnqueueAsync(
        string receiverId,
        string streamId,
        OutboxItem item,
        CancellationToken cancellationToken = default)
        => inner.EnqueueAsync(Own(receiverId), streamId, item, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<OutboxItem>> PendingAsync(
        string receiverId,
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default)
        => inner.PendingAsync(Own(receiverId), streamId, maxCount, cancellationToken);

    /// <inheritdoc />
    public Task AcknowledgeAsync(
        string receiverId,
        string streamId,
        IReadOnlyCollection<string> jwtIds,
        CancellationToken cancellationToken = default)
        => inner.AcknowledgeAsync(Own(receiverId), streamId, jwtIds, cancellationToken);

    /// <inheritdoc />
    public Task ClearAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => inner.ClearAsync(Own(receiverId), streamId, cancellationToken);

    private string Own(string receiverId)
    {
        guard.EnsureNotServedElsewhere();
        return TenantKey.Of(tenant, receiverId);
    }
}
