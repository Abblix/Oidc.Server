// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

/// <summary>
/// The names a tenant's settings build from its id.
/// </summary>
public class TenantIssuerSettingsTests
{
    private static TenantIssuerSettings SettingsOf(string id)
    {
        var served = new TenantContext
        {
            Tenant = new TenantDefinition { Id = id, Issuer = new Uri("https://auth.example.com/tenants/acme") },
        };
        return new TenantIssuerSettings(
            Mock.Of<ITenantAccessor>(accessor => accessor.Current == served),
            Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == new OidcOptions()),
            Mock.Of<ITenantCatalog>());
    }

    /// <summary>
    /// Tenants sharing a host share its cookies, so each tenant's check-session cookie carries its id.
    /// </summary>
    [Fact]
    public void TheCheckSessionCookie_CarriesTheTenantsId()
        => Assert.Equal(
            $"{new OidcOptions().CheckSessionCookie.Name}.acme-eu_1",
            SettingsOf("acme-eu_1").CheckSessionCookieName);

    /// <summary>
    /// A tenant a catalog of the host's own serves passes none of the server's checks, so one whose id could spell
    /// another tenant's cookie, or hold what a cookie name cannot, gets no cookie name at all.
    /// </summary>
    [Theory]
    [InlineData("acme.eu")]
    [InlineData("acme;eu")]
    [InlineData("acme eu")]
    public void ATenantThatCannotNameItsCookie_GetsNoCookieName(string id)
        => Assert.Throws<InvalidOperationException>(() => SettingsOf(id).CheckSessionCookieName);
}
