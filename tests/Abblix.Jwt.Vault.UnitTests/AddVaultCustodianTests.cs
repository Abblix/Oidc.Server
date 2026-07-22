// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// Verifies what is specific to <c>AddVaultCustodian</c>: the typed Transit client is pointed at the mount with
/// its auth header and registered as the custodian, and the placement call chained onto it installs the key provider.
/// What the placement call itself enforces is custodian-agnostic and lives in the core's own wiring tests.
/// </summary>
public class AddVaultCustodianTests
{
    private static void AddCustodian(IServiceCollection services)
    {
        // The placement call composes onto the in-process crypto backends, so they must be registered first - the same
        // order a host follows via AddOidcServices.
        services.AddJsonWebTokens();

        services.AddVaultCustodian(options =>
        {
            options.Address = "https://vault.test:8200";
            options.Token = "s.test-token";
            options.TransitMount = "transit";
        });
    }

    private static IServiceCollection Configure()
    {
        var services = new ServiceCollection();
        AddCustodian(services);

        // The external-keys provider is an add-on to an OIDC server, which supplies the options, the clock and
        // logging via AddOidcServices. Mirror that minimally here so the provider resolves without the whole stack.
        services.AddLogging();
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);
        return services;
    }

    /// <summary>
    /// What this package is responsible for: the Transit client is what answers as the custodian.
    /// </summary>
    /// <remarks>
    /// What is then done with that custodian - which key provider a placement call installs, and what guards a
    /// missing one - belongs to whoever consumes the keys, and is covered once in that consumer's own tests
    /// rather than repeated in every backend package.
    /// </remarks>
    [Fact]
    public void RegistersTheTransitClientAsTheCustodian()
    {
        var services = Configure();

        Assert.Contains(services, d => d.ServiceType == typeof(IKeyCustodian));

        using var provider = services.BuildServiceProvider();
        Assert.IsType<TransitCustodian>(provider.GetRequiredService<IKeyCustodian>());
    }

    [Fact]
    public void ConfiguresTheSharedClient_WithTheServerRootAddress()
    {
        using var provider = Configure().BuildServiceProvider();

        var http = provider.GetRequiredService<IHttpClientFactory>().CreateClient(Transport.ClientName);

        // The address stops at the server root rather than a mount: this one client also carries the key ring,
        // which lives on a different mount, so each engine spells its own into every path.
        Assert.Equal("https://vault.test:8200/v1/", http.BaseAddress!.ToString());

        // The token is NOT here: stamping it on the client would pin it for the process lifetime, and a token
        // minted by AppRole or Kubernetes auth is short-lived by design. It is applied per request instead.
        Assert.False(http.DefaultRequestHeaders.Contains(TokenHandler.TokenHeaderName));
    }

    [Fact]
    public void KeepsTheTokenOutOfLogs()
    {
        using var provider = Configure().BuildServiceProvider();

        // The token can sign tokens as this provider. IHttpClientFactory logs request headers at Trace and
        // redacts nothing by default, and Trace is exactly what an operator turns on to debug a Vault problem.
        var options = provider
            .GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>()
            .Get(Transport.ClientName);

        Assert.True(options.ShouldRedactHeaderValue(TokenHandler.TokenHeaderName));
    }
}
