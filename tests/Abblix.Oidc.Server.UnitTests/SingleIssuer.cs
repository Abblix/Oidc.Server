// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Moq;

namespace Abblix.Oidc.Server.UnitTests;

/// <summary>
/// Services built for the one tenant a test serves, from the settings <see cref="TestIssuer"/> describes, read at
/// each use as a reload of the tenant would be.
/// </summary>
internal static class SingleIssuer
{
    /// <summary>The settings a test describes nothing of.</summary>
    private static readonly TestIssuer Default = new();

    /// <summary>The tenant a test describes nothing of.</summary>
    public static TenantDefinition Tenant => Default.ToTenant();

    /// <summary>A request of the tenant a test describes nothing of.</summary>
    public static ITenantAccessor Accessor => AccessorOf(() => Default);

    /// <summary>A request of the tenant <paramref name="issuer"/> describes.</summary>
    public static ITenantAccessor AccessorOf(TestIssuer issuer) => AccessorOf(() => issuer);

    /// <summary>A request of the tenant <paramref name="issuer"/> describes.</summary>
    public static ITenantAccessor AccessorOf(IOptions<TestIssuer> issuer) => AccessorOf(() => issuer.Value);

    /// <summary>A request of the tenant <paramref name="issuer"/> describes as it reads at each question.</summary>
    public static ITenantAccessor AccessorOf(IOptionsMonitor<TestIssuer> issuer) => AccessorOf(() => issuer.CurrentValue);

    /// <summary>
    /// A request of the tenant <paramref name="current"/> describes, its definition built again from the settings
    /// at each question, so a changed setting is served as a changed definition would be.
    /// </summary>
    public static ITenantAccessor AccessorOf(Func<TestIssuer> current) => new CurrentTenant(current);

    /// <summary>
    /// The server's own catalog, serving the tenant a test describes nothing of, which the license vouches for and
    /// counts by the tenant's id, as it counts every server a test builds, so the tests of a run take one place
    /// between them.
    /// </summary>
    public static ITenantCatalog LicensedCatalog => Licensed;

    /// <summary>
    /// A catalog of the host's own: the license cannot vouch for a tenant it resolved, and counts it by the issuer each
    /// token names.
    /// </summary>
    public static ITenantCatalog HostCatalog { get; } = Mock.Of<ITenantCatalog>();

    public static ScopeManager ScopeManager() => new(LocalOf<Dictionary<string, ScopeDefinition>>());

    public static ResourceManager ResourceManager() => new(LocalOf<Dictionary<Uri, ResourceDefinition>>());

    /// <summary>
    /// The server's own subject type converter, issuing each tenant's subjects with the pairwise key it declares.
    /// </summary>
    public static ISubjectTypeConverter SubjectTypes() => new IssuerSubjectTypeConverter(LocalOf<SubjectTypeConverter>());

    /// <summary>
    /// A value kept for each tenant, built again once the tenant's definition hands out other objects.
    /// </summary>
    public static IIssuerLocal<T> LocalOf<T>() where T : class => new TenantIssuerLocal<T>(Catalog);

    /// <summary>
    /// The server's own catalog, over a store listing no tenant, so what is built from a tenant is built from the
    /// definition a test holds.
    /// </summary>
    public static ITenantCatalog Catalog { get; } = new ServedTenants().Catalog;

    /// <summary>
    /// The server's own catalog, serving the tenant a test describes nothing of, for the settings the license reads:
    /// it counts a tenant it serves by the tenant's id, as it counts every server a test builds, so the tests of a run
    /// take one place between them.
    /// </summary>
    private static readonly ITenantCatalog Licensed = ServingTheTenant();

    private static StoreTenantCatalog ServingTheTenant()
    {
        var tenants = new ServedTenants();
        tenants.ServeAsync(Default.ToTenant(), CancellationToken.None).GetAwaiter().GetResult();
        return tenants.Catalog;
    }

    private sealed class CurrentTenant(Func<TestIssuer> current) : ITenantAccessor
    {
        public TenantContext Current => new() { Tenant = current().ToTenant() };
    }
}
