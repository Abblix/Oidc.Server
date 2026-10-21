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
/// The server resolves its storage, its replay cache and its rate limiters in the form that keeps each tenant apart,
/// built over what is registered under these keys, so a host substitutes its own there, before or after registering
/// the server. Replacing the service the server resolves instead would let every tenant share one store or budget,
/// so startup refuses it.
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
