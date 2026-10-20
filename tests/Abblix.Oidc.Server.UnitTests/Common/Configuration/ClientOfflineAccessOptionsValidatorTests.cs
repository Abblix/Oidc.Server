// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A configured client's offline access is bound by its name, and a number configuration binds whatever its value is
/// refused at startup unless the enumeration names it.
/// </summary>
public class ClientOfflineAccessOptionsValidatorTests
{
    [Theory]
    [InlineData("Disabled", true)]
    [InlineData("ConsentRequired", true)]
    [InlineData("Allowed", true)]
    [InlineData("2", true)]
    [InlineData("7", false)]
    public void AConfiguredClient_StartsOnlyWithAnOfflineAccessTheEnumerationNames(string configured, bool starts)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Clients:0:ClientId"] = "configured",
                [$"Clients:0:{nameof(ClientInfo.OfflineAccess)}"] = configured,
            })
            .Build();
        var clients = configuration.GetSection(nameof(OidcOptions.Clients)).Get<ClientInfo[]>();

        var result = new ClientOfflineAccessOptionsValidator().Validate(null, new OidcOptions { Clients = clients! });

        Assert.Equal(starts, result.Succeeded);
    }
}
