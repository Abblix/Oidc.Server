// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Threading.RateLimiting;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// An endpoint's budget per caller - a client and, for a public one, its source address - spent separately for
/// each tenant.
/// </summary>
/// <remarks>The client id carries the tenant, which is enough to keep the two tenants' callers apart.</remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantCallerRateLimiter(
    PartitionedRateLimiter<(string ClientId, string? Source)> inner,
    ITenantAccessor tenantAccessor)
    : TenantPartitionedRateLimiter<(string ClientId, string? Source)>(inner)
{
    /// <inheritdoc />
    protected override (string ClientId, string? Source) Scope((string ClientId, string? Source) resource)
        => (TenantKey.Of(tenantAccessor, resource.ClientId), resource.Source);
}
