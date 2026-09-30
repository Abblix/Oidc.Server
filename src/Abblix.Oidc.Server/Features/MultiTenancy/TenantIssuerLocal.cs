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
    /// </remarks>
    public T GetOrCreate(object? source, Func<T> create)
    {
        var tenantId = TenantKey.CurrentTenantId(tenantAccessor);
        while (true)
        {
            var found = _values.TryGetValue(tenantId, out var built);
            if (found && ReferenceEquals(built!.Source, source))
                return built.Value;

            var fresh = new Built(source, create());
            if (found ? _values.TryUpdate(tenantId, fresh, built!) : _values.TryAdd(tenantId, fresh))
                return fresh.Value;
        }
    }

    // A class rather than a record: replacing a tenant's value compares the one it replaces by reference
    private sealed class Built(object? source, T value)
    {
        public object? Source { get; } = source;
        public T Value { get; } = value;
    }
}
