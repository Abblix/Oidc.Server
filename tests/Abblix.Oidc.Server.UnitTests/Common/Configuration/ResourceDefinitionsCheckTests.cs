// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// What a tenant's resource registry could not hold is refused at startup rather than when a request first builds it.
/// </summary>
public class ResourceDefinitionsCheckTests
{
    private static TenantDefinition TenantWith(params ResourceDefinition[] resources) => new()
    {
        Id = "acme",
        Issuer = new Uri("https://auth.example.com"),
        Resources = resources,
    };

    [Fact]
    public void AResourceNamedByARelativeAddress_IsRefused()
    {
        var refusals = new ResourceDefinitionsCheck()
            .Check([TenantWith(new ResourceDefinition(new Uri("api", UriKind.Relative)))], new OidcOptions())
            .ToList();

        var refusal = Assert.Single(refusals);
        Assert.Equal("acme", Assert.Single(refusal.TenantIds));
        Assert.Contains("The resource 'api' must be named by an absolute URI", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TwoResourcesUnderOneAddress_AreRefused()
    {
        var api = new Uri("https://api.example.com");

        var refusals = new ResourceDefinitionsCheck()
            .Check(
                [TenantWith(new ResourceDefinition(api, new ScopeDefinition("read")), new ResourceDefinition(api))],
                new OidcOptions())
            .ToList();

        var refusal = Assert.Single(refusals);
        Assert.Contains("2 resources are defined under 'https://api.example.com/'", refusal.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ResourcesUnderAddressesOfTheirOwn_PassTheCheck()
    {
        var refusals = new ResourceDefinitionsCheck().Check(
            [
                TenantWith(
                    new ResourceDefinition(new Uri("https://api.example.com")),
                    new ResourceDefinition(new Uri("https://files.example.com"))),
            ],
            new OidcOptions());

        Assert.Empty(refusals);
    }
}
