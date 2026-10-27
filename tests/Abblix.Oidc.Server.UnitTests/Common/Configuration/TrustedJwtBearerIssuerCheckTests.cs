// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A tenant of this server listed as a trusted issuer of the JWT bearer grant would have its revoked tokens accepted
/// as assertions, so the tenant is refused; a tenant at any other issuer is not.
/// </summary>
public class TrustedJwtBearerIssuerCheckTests
{
    private static List<TenantRefusal> Check(string tenantIssuer, params string[] trusted)
        => new TrustedJwtBearerIssuerCheck().Check(
            [new TenantDefinition { Id = "acme", Issuer = new Uri(tenantIssuer) }],
            new OidcOptions
            {
                JwtBearer = new JwtBearerOptions
                {
                    TrustedIssuers =
                    [
                        ..trusted.Select(issuer => new TrustedIssuer
                        {
                            Issuer = issuer,
                            JwksUri = new Uri("https://idp.example.com/jwks"),
                        }),
                    ],
                },
            }).ToList();

    /// <summary>
    /// A tenant whose issuer a trusted issuer names, as the grant compares them, scheme and host without regard to
    /// case, is refused, naming the tenant and the setting.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/tenants/acme")]
    [InlineData("HTTPS://Auth.Example.com/tenants/acme")]
    public void ATenantAtATrustedIssuer_IsRefused(string trusted)
    {
        var refusal = Assert.Single(Check("https://auth.example.com/tenants/acme", trusted));

        Assert.Equal("acme", Assert.Single(refusal.TenantIds));
        Assert.Contains(nameof(JwtBearerOptions.TrustedIssuers), refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A tenant at an issuer no trusted issuer names passes, a path differing in case included, so the refusal above
    /// is not a check refusing every tenant beside a trusted issuer.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/tenants/globex")]
    [InlineData("https://auth.example.com/tenants/ACME")]
    [InlineData("https://idp.example.com/tenants/acme")]
    public void ATenantAtAnotherIssuer_Passes(string trusted)
    {
        Assert.Empty(Check("https://auth.example.com/tenants/acme", trusted));
    }

    /// <summary>
    /// With no trusted issuer listed, nothing is refused.
    /// </summary>
    [Fact]
    public void NoTrustedIssuer_RefusesNothing()
    {
        Assert.Empty(Check("https://auth.example.com/tenants/acme"));
    }
}
