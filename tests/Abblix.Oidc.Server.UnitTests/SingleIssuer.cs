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
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Microsoft.Extensions.Options;
using Moq;

namespace Abblix.Oidc.Server.UnitTests;

/// <summary>
/// Services built for the one tenant a test serves, from the settings <see cref="TestIssuer"/> describes, read at
/// each use as a reload of the tenant would be.
/// </summary>
internal static class SingleIssuer
{
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

    public static ScopeManager ScopeManager(IOptions<TestIssuer> issuer)
        => new(SettingsOf(issuer), new TenantIssuerLocal<Dictionary<string, ScopeDefinition>>(
            AccessorOf(() => issuer.Value), Catalog));

    public static ResourceManager ResourceManager(IOptions<TestIssuer> issuer)
        => new(SettingsOf(issuer), new TenantIssuerLocal<Dictionary<Uri, ResourceDefinition>>(
            AccessorOf(() => issuer.Value), Catalog));

    /// <summary>
    /// A request of the tenant <paramref name="current"/> describes, its definition built again from the settings
    /// at each question, so a changed setting is served as a changed definition would be.
    /// </summary>
    public static ITenantAccessor AccessorOf(Func<TestIssuer> current) => new CurrentTenant(current);

    /// <summary>
    /// A value kept for the tenant <paramref name="current"/> describes, built again once its settings hand out other
    /// objects.
    /// </summary>
    public static IIssuerLocal<T> LocalOf<T>(Func<TestIssuer> current) where T : class
        => new TenantIssuerLocal<T>(AccessorOf(current), Catalog);

    /// <summary>A catalog of the host's own, which keeps nothing a test would have to arrange.</summary>
    private static ITenantCatalog Catalog => Mock.Of<ITenantCatalog>();

    private sealed class CurrentTenant(Func<TestIssuer> current) : ITenantAccessor
    {
        public TenantContext Current => new() { Tenant = current().ToTenant() };
    }
}
