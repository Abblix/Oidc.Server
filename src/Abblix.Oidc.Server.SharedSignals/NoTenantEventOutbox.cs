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
/// The outbox of the transmitter resolved where no tenant is served: every queued event belongs to a tenant's stream,
/// so every call is refused.
/// </summary>
internal sealed class NoTenantEventOutbox : IEventOutbox
{
    /// <inheritdoc />
    public Task EnqueueAsync(
        string receiverId,
        string streamId,
        OutboxItem item,
        CancellationToken cancellationToken = default)
        => throw NoTenant();

    /// <inheritdoc />
    public Task<IReadOnlyList<OutboxItem>> PendingAsync(
        string receiverId,
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default)
        => throw NoTenant();

    /// <inheritdoc />
    public Task AcknowledgeAsync(
        string receiverId,
        string streamId,
        IReadOnlyCollection<string> jwtIds,
        CancellationToken cancellationToken = default)
        => throw NoTenant();

    /// <inheritdoc />
    public Task ClearAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => throw NoTenant();

    private static InvalidOperationException NoTenant()
        => new("Every queued event belongs to a tenant's stream, and no tenant is served here.");
}
