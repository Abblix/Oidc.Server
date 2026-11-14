// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Refuses a part of a tenant's transmitter used where its tenant is not served, as one a host kept across requests
/// after resolving it for the tenant served then, which would put one tenant's events on another's streams or sign
/// them with another's keys.
/// </summary>
/// <remarks>
/// Once the tenant's creation is released, its parts serve only the deletion of its streams, which a host may set
/// off from a request of another tenant by changing the tenants, so they are no longer refused.
/// </remarks>
/// <param name="accessor">Names the tenant served when the part is used.</param>
/// <param name="tenant">The tenant the part was built for.</param>
/// <param name="released">Canceled once the tenant's creation is released.</param>
internal sealed class TenantPartGuard(ITenantAccessor accessor, TenantDefinition tenant, CancellationToken released)
{
    /// <summary>
    /// Passes where the part's own tenant is served, or once its creation is released.
    /// </summary>
    /// <exception cref="InvalidOperationException">Another tenant, or none, is served.</exception>
    public void EnsureServed()
    {
        var served = accessor.Current?.Tenant;
        if (released.IsCancellationRequested ||
            served is not null &&
            string.Equals(TenantKey.SpaceOf(served), TenantKey.SpaceOf(tenant), StringComparison.Ordinal))
        {
            return;
        }

        throw new InvalidOperationException(
            $"A part of the Shared Signals transmitter of the tenant '{tenant.Id}' is used where " +
            (served is null ? "no tenant is served" : $"the tenant '{served.Id}' is served") +
            ". Resolve the transmitter's parts in the request or tenant scope of the tenant they serve, rather " +
            "than keeping one across requests.");
    }
}
