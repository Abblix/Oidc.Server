// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// What the client and resource registries could not hold is refused at startup rather than when a request first
/// builds them.
/// </summary>
public class RegistryOptionsValidatorTests
{
    [Theory]
    [InlineData("app", "app")]
    [InlineData("App", "app")]
    public void TwoClientsUnderOneId_AreRefused(string first, string second)
    {
        var options = new OidcOptions { Clients = [new ClientInfo(first), new ClientInfo(second)] };

        var result = new ClientIdsOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains($"2 clients are configured under the id '{first}'", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void ClientsUnderIdsOfTheirOwn_PassTheCheck()
    {
        var options = new OidcOptions { Clients = [new ClientInfo("web"), new ClientInfo("mobile")] };

        Assert.True(new ClientIdsOptionsValidator().Validate(null, options).Succeeded);
    }

    [Fact]
    public void AResourceNamedByARelativeAddress_IsRefused()
    {
        var options = new OidcOptions { Resources = [new ResourceDefinition(new Uri("api", UriKind.Relative))] };

        var result = new ResourceDefinitionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("The resource 'api' must be named by an absolute URI", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void TwoResourcesUnderOneAddress_AreRefused()
    {
        var api = new Uri("https://api.example.com");
        var options = new OidcOptions
        {
            Resources = [new ResourceDefinition(api, new ScopeDefinition("read")), new ResourceDefinition(api)],
        };

        var result = new ResourceDefinitionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("2 resources are defined under 'https://api.example.com/'", result.FailureMessage,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ResourcesUnderAddressesOfTheirOwn_PassTheCheck()
    {
        var options = new OidcOptions
        {
            Resources =
            [
                new ResourceDefinition(new Uri("https://api.example.com")),
                new ResourceDefinition(new Uri("https://files.example.com")),
            ],
        };

        Assert.True(new ResourceDefinitionsValidator().Validate(null, options).Succeeded);
    }
}
