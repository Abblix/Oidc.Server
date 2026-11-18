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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A tenant's client's offline access is bound by its name, and a number configuration binds whatever its value is
/// refused at startup unless the enumeration names it.
/// </summary>
public class ClientOfflineAccessCheckTests
{
    [Theory]
    [InlineData("Disabled", true)]
    [InlineData("ConsentRequired", true)]
    [InlineData("Allowed", true)]
    [InlineData("2", true)]
    [InlineData("7", false)]
    public void ATenantsClient_StartsOnlyWithAnOfflineAccessTheEnumerationNames(string configured, bool starts)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Clients:0:ClientId"] = "configured",
                [$"Clients:0:{nameof(ClientInfo.OfflineAccess)}"] = configured,
            })
            .Build();
        var clients = configuration.GetSection(nameof(TenantDefinition.Clients)).Get<ClientInfo[]>();
        var tenant = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com"), Clients = clients! };

        var refusals = new ClientOfflineAccessCheck().Check([tenant], new OidcOptions());

        Assert.Equal(starts, !refusals.Any());
    }
}
