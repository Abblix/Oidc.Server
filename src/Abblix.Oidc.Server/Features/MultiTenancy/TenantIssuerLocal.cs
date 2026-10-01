// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.Issuer;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// One value for each tenant, since each tenant is an issuer.
/// </summary>
/// <remarks>
/// Outside any tenant there is no value to hand out, and the call refuses rather than answer with another tenant's.
/// </remarks>
/// <param name="tenantAccessor">Resolves the current tenant.</param>
/// <param name="catalog">The catalog the tenants are resolved from, asked whether it still serves the definition a
/// request holds.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantIssuerLocal<T>(ITenantAccessor tenantAccessor, ITenantCatalog catalog) : IIssuerLocal<T>
    where T : class
{
    private readonly ConcurrentDictionary<string, Built> _values = new(StringComparer.Ordinal);

    /// <inheritdoc />
    /// <remarks>
    /// Of two callers building a tenant's value at once, the one that stores it first wins and the other takes that
    /// value, so what either writes into it is kept.
    /// <para>
    /// A request begun before the tenant's definition changed holds the former one to its end. A value built from
    /// the definition in force (<see cref="StoreTenantCatalog.InForce"/>) is not replaced from any other: a request
    /// holding another is answered with it, rather than bring its definition back. A value built from any other
    /// definition is replaced by whichever request comes next. Where that catalog has no definition in force for
    /// this creation of the tenant, or is not the catalog in use, a changed source decides alone.
    /// </para>
    /// </remarks>
    public T GetOrCreate(object? source, Func<T> create)
    {
        var tenant = TenantKey.CurrentTenant(tenantAccessor);
        var space = TenantKey.SpaceOf(tenant);
        while (true)
        {
            var found = _values.TryGetValue(space, out var built);
            if (found && (ReferenceEquals(built!.Source, source) || !MayReplace(built, tenant)))
                return built.Value;

            var fresh = new Built(source, tenant, create());
            if (found ? _values.TryUpdate(space, fresh, built!) : _values.TryAdd(space, fresh))
                return fresh.Value;
        }
    }

    /// <summary>
    /// Whether <paramref name="built"/> may be replaced from <paramref name="tenant"/>: not when it was built from
    /// the definition in force and <paramref name="tenant"/> is another.
    /// </summary>
    private bool MayReplace(Built built, TenantDefinition tenant)
        => catalog is not StoreTenantCatalog own ||
           own.InForce(tenant) is not { } inForce ||
           ReferenceEquals(inForce, tenant) ||
           !ReferenceEquals(inForce, built.Definition);

    // A class rather than a record: replacing a tenant's value compares the one it replaces by reference
    private sealed class Built(object? source, TenantDefinition definition, T value)
    {
        public object? Source { get; } = source;
        public TenantDefinition Definition { get; } = definition;
        public T Value { get; } = value;
    }
}
