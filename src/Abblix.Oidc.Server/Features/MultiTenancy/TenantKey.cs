// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The key a stored value is kept under within the current tenant's space.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public static class TenantKey
{
    /// <summary>
    /// <paramref name="key"/> in the space of the tenant <paramref name="accessor"/> resolved.
    /// </summary>
    /// <remarks>
    /// The id's length goes before the id, because an id may hold the separator: without it tenant <c>a</c>
    /// with key <c>b:x</c> and tenant <c>a:b</c> with key <c>x</c> would be one entry.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// No tenant is resolved: a tenant's operation that lost its tenant on the way - work carried on after the
    /// request ended - would write where its tenant never reads, and the tenant would silently miss its data.
    /// </exception>
    public static string Of(ITenantAccessor accessor, string key)
    {
        var tenantId = accessor.Current?.Tenant.Id
            ?? throw new InvalidOperationException(
                "The operation runs outside any tenant, so there is no tenant's space to keep its data in. " +
                $"Run it within a request resolved to a tenant, or within {nameof(TenantScope)}.{nameof(TenantScope.Enter)}.");

        return string.Create(
            CultureInfo.InvariantCulture,
            $"tenant:{tenantId.Length}:{tenantId}:{key}");
    }
}
