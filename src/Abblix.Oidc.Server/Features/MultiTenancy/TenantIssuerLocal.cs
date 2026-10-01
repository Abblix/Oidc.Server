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
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantIssuerLocal<T>(ITenantAccessor tenantAccessor) : IIssuerLocal<T> where T : class
{
    private readonly ConcurrentDictionary<string, Built> _values = new(StringComparer.Ordinal);

    /// <inheritdoc />
    /// <remarks>
    /// Of two callers building a tenant's value at once, the one that stores it first wins and the other takes that
    /// value, so what either writes into it is kept.
    /// <para>
    /// A request begun before the tenant's definition changed holds the former one to its end. The value is not
    /// built back from a definition the server's catalog served before the one it was built from
    /// (<see cref="TenantDefinition.Revision"/>): that request is answered with the later value, rather than bring
    /// the former definition back - and, for the clients, drop a registration made since under an id the later
    /// one freed. A definition no such catalog ordered is told apart from the last one only by its source.
    /// </para>
    /// </remarks>
    public T GetOrCreate(object? source, Func<T> create)
    {
        var tenant = TenantKey.CurrentTenant(tenantAccessor);
        var space = TenantKey.SpaceOf(tenant);
        var revision = tenant.Revision;
        while (true)
        {
            var found = _values.TryGetValue(space, out var built);
            if (found && (ReferenceEquals(built!.Source, source) || revision < built.Revision))
                return built.Value;

            var fresh = new Built(source, revision, create());
            if (found ? _values.TryUpdate(space, fresh, built!) : _values.TryAdd(space, fresh))
                return fresh.Value;
        }
    }

    // A class rather than a record: replacing a tenant's value compares the one it replaces by reference
    private sealed class Built(object? source, long revision, T value)
    {
        public object? Source { get; } = source;
        public long Revision { get; } = revision;
        public T Value { get; } = value;
    }
}
