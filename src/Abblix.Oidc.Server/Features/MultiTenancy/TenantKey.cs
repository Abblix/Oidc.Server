// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Abblix.Jwt.ExternalKeys;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The key a stored value is kept under within the current tenant's space.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public static class TenantKey
{
    /// <summary>
    /// <paramref name="key"/> in the space of the tenant <paramref name="accessor"/> resolved.
    /// </summary>
    /// <remarks>
    /// The id's length goes before the id, because an id may hold the separator: without it tenant <c>a</c>
    /// with key <c>b:x</c> and tenant <c>a:b</c> with key <c>x</c> would be one entry.
    /// </remarks>
    /// <exception cref="InvalidOperationException">No tenant is resolved, as <see cref="CurrentTenant"/> says.
    /// </exception>
    public static string Of(ITenantAccessor accessor, string key)
        => string.Create(CultureInfo.InvariantCulture, $"tenant:{SpaceOf(CurrentTenant(accessor))}:{key}");

    /// <summary>
    /// What tells the space of <paramref name="tenant"/> from every other tenant's, this creation of its id
    /// included.
    /// </summary>
    /// <remarks>
    /// A tenant the settings declare has no generation and keeps the form a tenant had before generations, so
    /// what it stored stays its own. After the length-prefixed id comes either the end or the separator and the
    /// length-prefixed generation, so no id and generation spell another's.
    /// </remarks>
    internal static string SpaceOf(TenantDefinition tenant)
        => tenant.Generation.Length == 0
            ? string.Create(CultureInfo.InvariantCulture, $"{tenant.Id.Length}:{tenant.Id}")
            : string.Create(
                CultureInfo.InvariantCulture,
                $"{tenant.Id.Length}:{tenant.Id}{GenerationSeparator}{tenant.Generation.Length}:{tenant.Generation}");

    /// <summary>
    /// The space of the tenant <paramref name="accessor"/> resolved, as <see cref="SpaceOf"/> tells it.
    /// </summary>
    /// <exception cref="InvalidOperationException">No tenant is resolved, as <see cref="CurrentTenant"/> says.
    /// </exception>
    internal static string CurrentSpace(ITenantAccessor accessor) => SpaceOf(CurrentTenant(accessor));

    /// <summary>
    /// The partition of the key ring that keeps the keys the server mints for <paramref name="tenant"/>.
    /// </summary>
    /// <remarks>
    /// The separator is one neither a tenant id nor a generation may hold where the server mints the keys, so no
    /// id and generation name another's partition.
    /// </remarks>
    public static string PartitionOf(TenantDefinition tenant)
        => tenant.Generation.Length == 0 ? tenant.Id : $"{tenant.Id}{GenerationSeparator}{tenant.Generation}";

    /// <summary>
    /// Whether <paramref name="value"/> can stand on either side of the separator in a partition name.
    /// </summary>
    internal static bool IsPartitionSegment(string value)
        => KeyRingOptions.IsPartitionName(value) && !value.Contains(GenerationSeparator);

    private const char GenerationSeparator = '~';

    /// <summary>
    /// The tenant <paramref name="accessor"/> resolved.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// No tenant is resolved: a tenant's operation that lost its tenant on the way - work carried on after the
    /// request ended - would write where its tenant never reads, and the tenant would silently miss its data.
    /// </exception>
    internal static TenantDefinition CurrentTenant(ITenantAccessor accessor)
        => accessor.Current?.Tenant
           ?? throw new InvalidOperationException(
               "The operation runs outside any tenant, so it has no tenant's space to keep its data in and no " +
               "tenant's settings to follow. Run it within a request resolved to a tenant, or within " +
               $"{nameof(TenantScope)}.{nameof(TenantScope.Enter)}.");
}
