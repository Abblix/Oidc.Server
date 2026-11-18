// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The keys a host registers its own store or budget under, for the server to keep each tenant's part of it apart.
/// </summary>
/// <remarks>
/// A host substitutes its own storage, replay cache or rate limiters under these keys, before or after registering the
/// server. The server keeps each tenant's replay records and budgets apart over what is registered there, and
/// replacing the replay cache or a limiter the server resolves instead is refused at startup. The stores key every
/// entity by its tenant themselves, so a storage put in place of the one the server resolves still keeps the tenants
/// apart, but it is not measured: register it under <see cref="Shared"/> to keep the storage's metrics.
/// </remarks>
public static class TenantServiceKeys
{
    /// <summary>
    /// The key of the store every tenant's data is kept in, each tenant's under keys of its own: an
    /// <c>IEntityStorage</c> or an <c>IReplayCache</c>.
    /// </summary>
    public const string Shared = "Abblix.Oidc.Server.Shared";

    /// <summary>
    /// The key of the limiter that spends one tenant's <paramref name="budget"/>, resolved once for each tenant, so
    /// it is registered with a factory or a type that builds a new limiter every time.
    /// </summary>
    /// <param name="budget">The budget, as <c>CallerRateLimiters</c> names it.</param>
    public static string PerTenant(string budget) => $"{budget}.{nameof(PerTenant)}";
}
