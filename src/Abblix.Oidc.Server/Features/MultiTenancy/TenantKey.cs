// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The key a stored value is kept under within the current tenant's space.
/// </summary>
public static class TenantKey
{
    private const char GenerationSeparator = '~';

    private const string Naming = "a tenant's id and generation may hold only ASCII letters, digits, '-' and '_'.";

    /// <summary>
    /// <paramref name="key"/> in the space of <paramref name="tenant"/>.
    /// </summary>
    /// <remarks>
    /// The space holds no separator of the key, so tenant <c>a</c> with key <c>b:x</c> and tenant <c>a:b</c> with
    /// key <c>x</c> cannot be one entry: a tenant named <c>a:b</c> builds no key at all.
    /// </remarks>
    /// <exception cref="InvalidOperationException"><paramref name="tenant"/> is not named as <see cref="IsNamed"/>
    /// requires.</exception>
    public static string Of(TenantDefinition tenant, string key)
        => string.Create(CultureInfo.InvariantCulture, $"tenant:{SpaceOf(tenant)}:{key}");

    /// <summary>
    /// What tells the space of <paramref name="tenant"/> from every other tenant's, this creation of its id
    /// included: the id, followed by the separator and the generation when it has one.
    /// </summary>
    /// <exception cref="InvalidOperationException"><paramref name="tenant"/> is not named as <see cref="IsNamed"/>
    /// requires.</exception>
    internal static string SpaceOf(TenantDefinition tenant) => PartitionOf(tenant);

    /// <summary>
    /// The partition of the key ring that keeps the keys the server mints for <paramref name="tenant"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException"><paramref name="tenant"/> is not named as <see cref="IsNamed"/>
    /// requires.</exception>
    public static string PartitionOf(TenantDefinition tenant)
    {
        var id = IdOf(tenant);
        return tenant.Generation.Length == 0 ? id : $"{id}{GenerationSeparator}{tenant.Generation}";
    }

    /// <summary>
    /// The id of <paramref name="tenant"/>, to build a name from.
    /// </summary>
    /// <remarks>
    /// Wherever the server takes a tenant in, one that is not named is refused, but a host may serve tenants from a
    /// catalog of its own, which nothing of the server judges. A name built from such a tenant could spell another
    /// tenant's, and its requests would read and write that tenant's data, so building one fails instead.
    /// </remarks>
    /// <exception cref="InvalidOperationException"><paramref name="tenant"/> is not named as <see cref="IsNamed"/>
    /// requires.</exception>
    internal static string IdOf(TenantDefinition tenant)
        => IsNamed(tenant)
            ? tenant.Id
            : throw new InvalidOperationException(
                $"The tenant '{tenant.Id}' in generation '{tenant.Generation}' cannot name its data: {Naming}");

    /// <summary>
    /// Whether the id of <paramref name="tenant"/>, and its generation when it has one, can stand in every name
    /// built from them: storage keys, the key ring partition and the check-session cookie name.
    /// </summary>
    /// <remarks>
    /// Neither holds a separator those names use, so no id and generation spell another's, and the names need no
    /// escaping.
    /// </remarks>
    internal static bool IsNamed(TenantDefinition tenant)
        => IsName(tenant.Id) && (tenant.Generation.Length == 0 || IsName(tenant.Generation));

    /// <summary>
    /// Refuses each of <paramref name="tenants"/> that is not named as <see cref="IsNamed"/> requires.
    /// </summary>
    /// <remarks>
    /// Every way a tenant enters the server - the settings at startup, a reading of the store of tenants, a change
    /// through the tenant manager - judges it by this as well as by the checks of the tenant list
    /// (<see cref="TenantRefusal.AllOf"/>). A host can replace those checks but not this, since a tenant it lets
    /// through would share another tenant's data.
    /// </remarks>
    internal static IEnumerable<TenantRefusal> Unnamed(IEnumerable<TenantDefinition> tenants)
    {
        foreach (var tenant in tenants)
        {
            if (string.IsNullOrEmpty(tenant.Id))
            {
                yield return TenantRefusal.Of(
                    tenant,
                    $"A tenant with the issuer '{tenant.Issuer?.OriginalString}' has no id.");
            }
            else if (!IsName(tenant.Id))
            {
                yield return TenantRefusal.Of(tenant, $"The id of tenant '{tenant.Id}' is refused: {Naming}");
            }

            if (tenant.Generation.Length > 0 && !IsName(tenant.Generation))
            {
                yield return TenantRefusal.Of(
                    tenant,
                    $"The generation '{tenant.Generation}' of tenant '{tenant.Id}' is refused: {Naming}");
            }
        }
    }

    private static bool IsName(string? value)
        => !string.IsNullOrEmpty(value) && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>
    /// The tenant <paramref name="accessor"/> resolved.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// No tenant is resolved: a tenant's operation that lost its tenant on the way - work carried on after the
    /// request ended - would write where its tenant never reads, and the tenant would silently miss its data.
    /// </exception>
    public static TenantDefinition CurrentTenant(this ITenantAccessor accessor)
        => accessor.Current?.Tenant
           ?? throw new InvalidOperationException(
               "The operation runs outside any tenant, so it has no tenant's space to keep its data in and no " +
               "tenant's settings to follow. Run it within a request resolved to a tenant, or within " +
               $"{nameof(TenantScope)}.{nameof(TenantScope.Enter)}.");
}
