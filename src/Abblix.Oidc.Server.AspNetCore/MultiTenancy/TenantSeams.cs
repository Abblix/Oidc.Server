// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Threading.RateLimiting;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Every service holding data a tenant owns, each with the wrapper that keeps it per tenant.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal static class TenantSeams
{
    /// <summary>
    /// The services, in the order they are wrapped.
    /// </summary>
    /// <remarks>
    /// The entity storage carries every store built on it - codes, pushed and polled requests, token statuses,
    /// session registries, rate-limit counters, the nonce secret. The replay cache and the per-caller budgets
    /// keep their data outside it.
    /// </remarks>
    public static readonly ITenantSeam[] All =
    [
        new DecoratedTenantSeam<IEntityStorage, TenantEntityStorage>(),
        new DecoratedTenantSeam<IReplayCache, TenantReplayCache>(),
        new RateLimiterTenantSeam<string>(CallerRateLimiters.AuthenticationFailures),
        new RateLimiterTenantSeam<(string ClientId, string? Source)>(CallerRateLimiters.Introspection, required: false),
        new RateLimiterTenantSeam<(string ClientId, string? Source)>(CallerRateLimiters.Revocation, required: false),
    ];
}
