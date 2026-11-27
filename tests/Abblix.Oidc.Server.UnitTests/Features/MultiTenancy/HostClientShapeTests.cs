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
using Abblix.Oidc.Server.Features.MultiTenancy;
using HostApplication.Clients;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

/// <summary>
/// A host's own client type, derived from the server's, holding a null where the server's type declares a value is
/// refused for it like the server's own client, rather than reaching a check that reads the value.
/// </summary>
public class HostClientShapeTests
{
    [Fact]
    public void AHostClientWithANullSecret_IsRefusedForIt_WithoutThrowing()
    {
        var tenant = new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri("https://auth.example.com"),
            Clients = [new HostClient("web") { ClientSecrets = [null!] }],
        };
        ITenantsCheck[] checks = [new ClientSecretsCheck()];

        var refusals = TenantRefusal.AllOf(checks, [tenant], new OidcOptions()).ToArray();

        Assert.Equal(["Clients['web'].ClientSecrets[0]"], TenantShape.NullsOf(tenant));
        Assert.Contains(refusals, refusal => refusal.TenantIds.Contains("acme"));
    }
}
