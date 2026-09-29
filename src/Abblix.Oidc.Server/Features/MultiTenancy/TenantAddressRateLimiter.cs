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
/// The budget of failed client authentications, partitioned by source address, spent separately for each tenant.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantAddressRateLimiter(PartitionedRateLimiter<string> inner, ITenantAccessor tenantAccessor)
    : TenantPartitionedRateLimiter<string>(inner)
{
    /// <inheritdoc />
    protected override string Scope(string resource) => TenantKey.Of(tenantAccessor, resource);
}
