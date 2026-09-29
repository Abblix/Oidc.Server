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
    private readonly ConcurrentDictionary<string, T> _values = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public T GetOrCreate(Func<T> create)
        => _values.GetOrAdd(TenantKey.CurrentTenantId(tenantAccessor), _ => create());
}
