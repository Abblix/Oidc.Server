// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// The tenant and creation a refresh token was issued at, named in it as the key ring's partition of that tenant is
/// named. What is recorded about a refresh token is kept for that tenant and creation, so a token is renewed only at
/// the one it names.
/// </summary>
internal static class RefreshTokenTenant
{
    /// <summary>
    /// The private claim the tenant is named under, read back only by this server.
    /// </summary>
    internal const string ClaimType = "abblix_tenant";

    /// <summary>
    /// Names the tenant <paramref name="tenantAccessor"/> resolves in <paramref name="payload"/>.
    /// </summary>
    public static void NameCurrent(JsonWebTokenPayload payload, ITenantAccessor tenantAccessor)
        => payload.Json.SetProperty(ClaimType, TenantKey.PartitionOf(tenantAccessor.CurrentTenant()));

    /// <summary>
    /// Whether <paramref name="payload"/> names the tenant <paramref name="tenantAccessor"/> resolves; a refresh
    /// token issued before 3.0 names none.
    /// </summary>
    public static bool NamesCurrent(JsonWebTokenPayload payload, ITenantAccessor tenantAccessor)
        => payload.Json.GetProperty<string>(ClaimType) == TenantKey.PartitionOf(tenantAccessor.CurrentTenant());
}
