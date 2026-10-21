// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
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

    public static IIssuerSettings Settings => SettingsOf(new TestIssuer());

    public static IIssuerSettings SettingsOf(TestIssuer issuer) => SettingsOf(() => issuer);

    public static IIssuerSettings SettingsOf(IOptions<TestIssuer> issuer) => SettingsOf(() => issuer.Value);

    public static IIssuerSettings SettingsOf(IOptionsMonitor<TestIssuer> issuer) => SettingsOf(() => issuer.CurrentValue);

    /// <summary>
    /// The settings of the tenant <paramref name="current"/> describes at the moment they are read.
    /// </summary>
    public static IIssuerSettings SettingsOf(Func<TestIssuer> current)
        => SettingsOf(current, new OidcOptions());

    /// <summary>
    /// The settings of the tenant <paramref name="issuer"/> describes, or of a bare one, on a server set up by
    /// <paramref name="server"/>.
    /// </summary>
    public static IIssuerSettings SettingsOf(IOptions<OidcOptions> server, TestIssuer? issuer = null)
    {
        var tenant = issuer ?? new TestIssuer();
        return SettingsOf(() => tenant, server.Value);
    }

    /// <summary>
    /// The settings of a bare tenant whose keys <paramref name="custodianKeys"/> names, on a server set up by
    /// <paramref name="server"/>.
    /// </summary>
    public static IIssuerSettings SettingsOf(IOptions<OidcOptions> server, CustodianHeldKeys custodianKeys)
        => SettingsOf(server, new TestIssuer { CustodianKeys = custodianKeys });

    /// <summary>
    /// The settings of the tenant <paramref name="current"/> describes, on a server set up by
    /// <paramref name="server"/>, both read at each use.
    /// </summary>
    public static IIssuerSettings SettingsOf(Func<TestIssuer> current, OidcOptions server)
        => new TenantIssuerSettings(
            AccessorOf(current),
            Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == server),
            Catalog);

    /// <summary>
    /// The settings of the tenant <paramref name="current"/> describes, resolved by a catalog of the host's own: the
    /// license cannot vouch for such a tenant, and counts it by the issuer each token names.
    /// </summary>
    public static IIssuerSettings HostCatalogSettingsOf(Func<TestIssuer> current)
        => new TenantIssuerSettings(
            AccessorOf(current),
            Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == new OidcOptions()),
            Mock.Of<ITenantCatalog>());

    /// <summary>The settings of a bare tenant a catalog of the host's own resolved.</summary>
    public static IIssuerSettings HostCatalogSettings => HostCatalogSettingsOf(() => new TestIssuer());

    public static ScopeManager ScopeManager() => new(LocalOf<Dictionary<string, ScopeDefinition>>());

    public static ResourceManager ResourceManager() => new(LocalOf<Dictionary<Uri, ResourceDefinition>>());

    /// <summary>
    /// The server's own subject type converter, issuing each tenant's subjects with the pairwise key it declares.
    /// </summary>
    public static ISubjectTypeConverter SubjectTypes() => new IssuerSubjectTypeConverter(LocalOf<SubjectTypeConverter>());

    /// <summary>
    /// A request of the tenant <paramref name="current"/> describes, its definition built again from the settings
    /// at each question, so a changed setting is served as a changed definition would be.
    /// </summary>
    public static ITenantAccessor AccessorOf(Func<TestIssuer> current) => new CurrentTenant(current);

    /// <summary>
    /// A value kept for each tenant, built again once the tenant's definition hands out other objects.
    /// </summary>
    public static IIssuerLocal<T> LocalOf<T>() where T : class => new TenantIssuerLocal<T>(Catalog);

    /// <summary>
    /// The server's own catalog, over a store listing no tenant: the license counts a tenant it vouches for by the
    /// tenant's id, as it counts every server a test builds, so the tests of a run take one place between them.
    /// </summary>
    public static ITenantCatalog Catalog { get; } = new ServedTenants().Catalog;

    private sealed class CurrentTenant(Func<TestIssuer> current) : ITenantAccessor
    {
        public TenantContext Current => new() { Tenant = current().ToTenant() };
    }
}
