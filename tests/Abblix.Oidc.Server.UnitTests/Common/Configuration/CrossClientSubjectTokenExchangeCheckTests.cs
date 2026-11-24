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
/// A tenant's client's cross-client subject token exchange setting is bound by its name, and a number configuration
/// binds whatever its value is refused at startup unless the enumeration names it.
/// </summary>
public class CrossClientSubjectTokenExchangeCheckTests
{
    private const string Issuer = "https://auth.example.com";

    [Theory]
    [InlineData("Refused", true)]
    [InlineData("Any", true)]
    [InlineData("2", true)]
    [InlineData("3", false)]
    public void ATenantsClient_StartsOnlyWithASettingTheEnumerationNames(string configured, bool starts)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Clients:0:ClientId"] = "configured",
                [$"Clients:0:{nameof(ClientInfo.CrossClientSubjectTokenExchange)}"] = configured,
            })
            .Build();
        var clients = configuration.GetSection(nameof(TenantDefinition.Clients)).Get<ClientInfo[]>();
        var tenant = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com"), Clients = clients! };

        var refusals = new CrossClientSubjectTokenExchangeCheck().Check([tenant], new OidcOptions());

        Assert.Equal(starts, !refusals.Any());
    }

    /// <summary>
    /// A client exchanging tokens addressed to it starts only naming a location of its own, and none of its locations
    /// may be the issuer, the audience of every access token whose request named no resource.
    /// </summary>
    [Theory]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, new[] { "https://mcp.example.com/" }, true)]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, new string[0], false)]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, null, false)]
    [InlineData(CrossClientSubjectTokenExchange.AddressedToClient, new[] { "https://mcp.example.com/", Issuer }, false)]
    [InlineData(CrossClientSubjectTokenExchange.Refused, new[] { Issuer }, false)]
    [InlineData(CrossClientSubjectTokenExchange.Refused, null, true)]
    [InlineData(CrossClientSubjectTokenExchange.Any, null, true)]
    public void AClient_StartsOnlyWithLocationsItsSettingCanUse(
        CrossClientSubjectTokenExchange setting,
        string[]? locations,
        bool starts)
    {
        var client = new ClientInfo("configured")
        {
            CrossClientSubjectTokenExchange = setting,
            ResourceLocations = locations?.Select(location => new Uri(location)).ToArray(),
        };
        var tenant = new TenantDefinition { Id = "acme", Issuer = new Uri(Issuer), Clients = [client] };

        var refusals = new CrossClientSubjectTokenExchangeCheck().Check([tenant], new OidcOptions()).ToArray();

        Assert.Equal(starts, refusals.Length == 0);
    }
}
