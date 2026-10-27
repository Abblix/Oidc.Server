// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

/// <summary>
/// An issuer is found to be a tenant this server serves the way a request to the tenant finds it: at the address the
/// catalog keeps the tenant under, its path decoded.
/// </summary>
public class TenantIssuersTests
{
    private static readonly TenantDefinition Cafe = new()
    {
        Id = "cafe",
        Issuer = new Uri("https://auth.example.com/tenants/café"),
    };

    /// <summary>
    /// A catalog that, as the server's own does, answers for the decoded path of the tenant's issuer alone.
    /// </summary>
    private static ITenantCatalog Catalog()
    {
        var catalog = new Mock<ITenantCatalog>();
        catalog
            .Setup(c => c.FindByAddressAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string host, string path, CancellationToken _) =>
                host == "auth.example.com" && path == "/tenants/café" ? Cafe : null);
        return catalog.Object;
    }

    /// <summary>
    /// The issuer of a tenant whose path holds a character a URI escapes is found, written either way, and an issuer
    /// the catalog does not serve is not.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/tenants/café", true)]
    [InlineData("https://auth.example.com/tenants/caf%C3%A9", true)]
    [InlineData("https://auth.example.com/tenants/cafe", false)]
    [InlineData("not a uri", false)]
    public async Task AnIssuer_IsFoundAsATenantTheCatalogServes(string issuer, bool served)
    {
        Assert.Equal(served, await Catalog().ServesAsync(issuer, CancellationToken.None));
    }
}
