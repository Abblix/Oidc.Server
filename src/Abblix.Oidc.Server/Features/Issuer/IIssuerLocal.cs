// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// A value a service builds once for each tenant it serves, such as a registry built from what the tenant
/// declares.
/// </summary>
/// <remarks>
/// Each service that asks for one gets its own, so two services keeping values of the same type never share them,
/// and the values last as long as that service does: one registered per request builds them for every request.
/// </remarks>
/// <typeparam name="T">The type of the value.</typeparam>
public interface IIssuerLocal<T> where T : class
{
    /// <summary>
    /// The value for <paramref name="tenant"/>, built by <paramref name="create"/> from <paramref name="source"/> the
    /// first time that tenant asks for it, and built again whenever the tenant's source is another object - as its
    /// definition is after a change.
    /// </summary>
    /// <remarks>
    /// The source is compared by reference: what a tenant declares is the same object until its definition changes.
    /// </remarks>
    /// <param name="tenant">The tenant the value is kept for.</param>
    /// <param name="source">What the value is built from.</param>
    /// <param name="create">Builds the value.</param>
    T GetOrCreate(TenantDefinition tenant, object? source, Func<T> create);
}
