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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// What a tenant's client registry could not hold is refused at startup rather than when a request first builds it.
/// </summary>
public class ClientIdsCheckTests
{
    private static TenantDefinition TenantWith(params ClientInfo[] clients) => new()
    {
        Id = "acme",
        Issuer = new Uri("https://auth.example.com"),
        Clients = clients,
    };

    [Theory]
    [InlineData("app", "app")]
    [InlineData("App", "app")]
    public void TwoClientsUnderOneId_AreRefused(string first, string second)
    {
        var refusals = new ClientIdsCheck()
            .Check([TenantWith(new ClientInfo(first), new ClientInfo(second))], new OidcOptions())
            .ToList();

        var refusal = Assert.Single(refusals);
        Assert.Equal("acme", Assert.Single(refusal.TenantIds));
        Assert.Contains($"2 clients are configured under the id '{first}'", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ClientsUnderIdsOfTheirOwn_PassTheCheck()
    {
        var refusals = new ClientIdsCheck()
            .Check([TenantWith(new ClientInfo("web"), new ClientInfo("mobile"))], new OidcOptions());

        Assert.Empty(refusals);
    }

    /// <summary>
    /// A client is known only at the tenant that lists it, so two tenants may each register a client under the same
    /// id; the check judges each tenant's registry on its own.
    /// </summary>
    [Fact]
    public void OneIdAtTwoTenants_PassesTheCheck()
    {
        var globex = new TenantDefinition
        {
            Id = "globex",
            Issuer = new Uri("https://globex.example.com"),
            Clients = [new ClientInfo("app")],
        };

        var refusals = new ClientIdsCheck().Check([TenantWith(new ClientInfo("app")), globex], new OidcOptions());

        Assert.Empty(refusals);
    }
}
