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
/// Keeps each tenant's delivery claims apart in a lease shared by every tenant.
/// </summary>
/// <remarks>
/// A claim is named after its stream, and a stream a tenant declares carries the identifier its operator chose, so
/// two tenants may hold streams of one name: prefixed with the tenant's space, the claim on one of them does not hold
/// back delivery to the other.
/// </remarks>
/// <param name="inner">The lease every tenant shares.</param>
/// <param name="tenant">The tenant whose claims these are.</param>
internal sealed class TenantDeliveryLease(IDeliveryLease inner, TenantDefinition tenant) : IDeliveryLease
{
    /// <inheritdoc />
    public Task<IAsyncDisposable?> TryAcquireAsync(
        string name,
        TimeSpan duration,
        CancellationToken cancellationToken = default)
        => inner.TryAcquireAsync(TenantKey.Of(tenant, name), duration, cancellationToken);
}
