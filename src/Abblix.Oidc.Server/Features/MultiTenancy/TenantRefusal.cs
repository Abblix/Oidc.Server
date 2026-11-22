// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Why a check of a tenant list refuses some of its tenants.
/// </summary>
/// <param name="TenantIds">The tenants refused: one for a mistake of its own, every party to a conflict between
/// several.</param>
/// <param name="Message">What is wrong, naming the tenants.</param>
public sealed record TenantRefusal(IReadOnlyCollection<string> TenantIds, string Message)
{
    /// <summary>
    /// What is wrong with a conflict between several tenants as told to one of them, naming none of the tenants,
    /// since the party changing one tenant may not be entitled to learn which others exist; null for a refusal of
    /// one tenant alone. A host's own check may leave it null for a conflict too, and the party is then told only
    /// that its tenant conflicts with another, which the host's log names.
    /// </summary>
    public string? PartyMessage { get; init; }

    /// <summary>
    /// A refusal of <paramref name="tenant"/> alone.
    /// </summary>
    public static TenantRefusal Of(TenantDefinition tenant, string message) => new([tenant.Id], message);

    /// <summary>
    /// Everything that refuses tenants in <paramref name="tenants"/>: a tenant that cannot name its data, as
    /// <see cref="TenantKey.Unnamed"/> tells, a null where the tenant's types declare a value, as
    /// <see cref="TenantShape"/> finds, and whatever <paramref name="checks"/> refuse of the rest.
    /// </summary>
    /// <remarks>
    /// Every way a tenant enters the server judges it by this, so the host's choice of checks never lets in a tenant
    /// that would share another's data.
    /// </remarks>
    internal static IEnumerable<TenantRefusal> AllOf(
        IEnumerable<ITenantsCheck> checks,
        IReadOnlyCollection<TenantDefinition> tenants,
        OidcOptions options)
    {
        var shapes = tenants.Select(tenant => (Tenant: tenant, Nulls: TenantShape.NullsOf(tenant).ToArray())).ToArray();

        // A tenant holding a null where a value is declared is refused for it, and the checks, which read the
        // definition as declared, see it mended (TenantShape.Readable): it still claims its address and keys, so a
        // tenant claiming the same is refused for the conflict
        var refusedForNull = shapes
            .Where(shape => shape.Nulls.Length > 0)
            .Select(shape => shape.Tenant.Id)
            .ToHashSet(StringComparer.Ordinal);

        TenantDefinition[] readable =
        [
            ..shapes.Select(shape => shape.Nulls.Length == 0 ? shape.Tenant : TenantShape.Readable(shape.Tenant)),
        ];

        // What the checks find wrong with such a tenant alone is not told: the mending causes some of it - signing
        // keys left empty once a null key is dropped, a client left with no secret - and nothing tells those from its
        // other faults, which therefore show once the null is mended in the definition itself
        return TenantKey.Unnamed(tenants)
            .Concat(
                from shape in shapes
                from path in shape.Nulls
                select Of(shape.Tenant, $"Tenant '{shape.Tenant.Id}': {path} is null, where a value is required."))
            .Concat(
                from check in checks
                from refusal in check.Check(readable, options)
                where refusal.TenantIds.Count == 0 || !refusal.TenantIds.All(refusedForNull.Contains)
                select refusal);
    }

    /// <summary>
    /// The refusals of each of <paramref name="tenants"/> that <paramref name="failures"/> finds wrong with it alone,
    /// each naming the tenant.
    /// </summary>
    internal static IEnumerable<TenantRefusal> EachOf(
        IEnumerable<TenantDefinition> tenants,
        Func<TenantDefinition, IEnumerable<string>> failures)
        =>
            from tenant in tenants
            from failure in failures(tenant)
            select Of(tenant, $"Tenant '{tenant.Id}': {failure}");
}
