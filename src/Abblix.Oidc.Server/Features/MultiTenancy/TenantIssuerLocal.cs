// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
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

    // The sources a newer one replaced, held weakly so a replaced definition can still be collected
    private readonly ConditionalWeakTable<object, object> _superseded = new();

    /// <inheritdoc />
    /// <remarks>
    /// Of two callers building a tenant's value at once, the one that stores it first wins and the other takes that
    /// value, so what either writes into it is kept.
    /// <para>
    /// A request begun before the tenant's definition changed holds the former one to its end, and asks with its
    /// source. The value is not built back from a source a newer one replaced: that request is answered with the
    /// newer value, rather than bring the former definition back - and, for the clients, drop a registration made
    /// since under an id the newer one freed.
    /// </para>
    /// </remarks>
    public T GetOrCreate(object? source, Func<T> create)
    {
        var space = TenantKey.CurrentSpace(tenantAccessor);
        while (true)
        {
            var found = _values.TryGetValue(space, out var built);
            if (found && (ReferenceEquals(built!.Source, source) || IsSuperseded(source)))
                return built.Value;

            var fresh = new Built(source, create());
            if (found ? _values.TryUpdate(space, fresh, built!) : _values.TryAdd(space, fresh))
            {
                if (found && built!.Source is { } replaced)
                    _superseded.TryAdd(replaced, replaced);

                return fresh.Value;
            }
        }
    }

    private bool IsSuperseded(object? source) => source is not null && _superseded.TryGetValue(source, out _);

    // A class rather than a record: replacing a tenant's value compares the one it replaces by reference
    private sealed class Built(object? source, T value)
    {
        public object? Source { get; } = source;
        public T Value { get; } = value;
    }
}
