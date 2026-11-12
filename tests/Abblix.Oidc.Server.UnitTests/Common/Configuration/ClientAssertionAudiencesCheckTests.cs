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
/// A tenant's client's assertion audiences are bound as configuration writes a set of flags, a value left at zero reads
/// as the issuer alone, and a non-zero set lacking the issuer identifier, or holding a bit the enumeration does not
/// define, is refused at startup.
/// </summary>
public class ClientAssertionAudiencesCheckTests
{
    [Theory]
    [InlineData(null, true)]
    [InlineData("Issuer", true)]
    [InlineData("Issuer, TokenEndpoint", true)]
    [InlineData("Issuer, AllowArray", true)]
    [InlineData("Issuer, TokenEndpoint, AllowArray", true)]
    [InlineData("TokenEndpoint", false)]
    [InlineData("AllowArray", false)]
    [InlineData("TokenEndpoint, AllowArray", false)]
    [InlineData("7", true)]
    [InlineData("0", true)]
    [InlineData("9", false)]
    public void ATenantsClient_StartsOnlyWithAssertionAudiencesHoldingTheIssuer(string? configured, bool starts)
        => Assert.Equal(starts, !Refusals(Bind(configured)).Any());

    /// <summary>
    /// What a host writes is what the server applies, so a set the check lets through is the set it was written as,
    /// its names read in any case, a number read as the bits it holds, and an unset or zero value is the issuer alone.
    /// </summary>
    [Theory]
    [InlineData(null, ClientAssertionAudiences.Issuer)]
    [InlineData("0", ClientAssertionAudiences.Issuer)]
    [InlineData("issuer", ClientAssertionAudiences.Issuer)]
    [InlineData("Issuer, TokenEndpoint", ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint)]
    [InlineData("Issuer, AllowArray", ClientAssertionAudiences.Issuer | ClientAssertionAudiences.AllowArray)]
    [InlineData("7", ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint | ClientAssertionAudiences.AllowArray)]
    public void ATenantsClient_ReadsItsAssertionAudiencesAsWritten(string? configured, ClientAssertionAudiences read)
        => Assert.Equal(read, Bind(configured).ClientAssertionAudiences);

    private static IEnumerable<TenantRefusal> Refusals(ClientInfo client)
    {
        var tenant = new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri("https://auth.example.com"),
            Clients = [client],
        };

        return new ClientAssertionAudiencesCheck().Check([tenant], new OidcOptions());
    }

    /// <summary>
    /// Binds one client from configuration that writes <paramref name="configured"/> as its assertion audiences, or
    /// leaves them out when it is null.
    /// </summary>
    private static ClientInfo Bind(string? configured)
    {
        var settings = new Dictionary<string, string?> { ["Clients:0:ClientId"] = "configured" };
        if (configured is not null)
            settings[$"Clients:0:{nameof(ClientInfo.ClientAssertionAudiences)}"] = configured;

        return new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build()
            .GetSection(nameof(TenantDefinition.Clients))
            .Get<ClientInfo[]>()!
            .Single();
    }
}
