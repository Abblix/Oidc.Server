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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.Vault.UnitTests;

/// <summary>
/// Verifies what is specific to <c>AddVaultCustodian</c>: the typed Transit client is pointed at the mount with
/// its auth header and registered as the custodian, and the tier call chained onto it installs the key provider.
/// What the tier call itself enforces is custodian-agnostic and lives in the core's own wiring tests.
/// </summary>
public class AddVaultCustodianTests
{
    private static IKeyCustodianBuilder AddCustodian(IServiceCollection services)
    {
        // The tier call composes onto the in-process crypto backends, so they must be registered first - the same
        // order a host follows via AddOidcServices.
        services.AddJsonWebTokens();

        return services.AddVaultCustodian(options =>
        {
            options.Address = "https://vault.test:8200";
            options.Token = "s.test-token";
            options.TransitMount = "transit";
        });
    }

    private static IServiceCollection Configure()
    {
        var services = new ServiceCollection();
        AddCustodian(services).HoldKeysInCustodian(new CustodianHeldKeys
        {
            SigningKeyName = "oidc-sign",
            EncryptionKeyName = "oidc-enc",
        });

        // The external-keys provider is an add-on to an OIDC server, which supplies the options and the clock via
        // AddOidcServices. Mirror that minimally here so the provider resolves without the whole OIDC stack.
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);
        return services;
    }

    [Fact]
    public void RegistersCustodianAndKeyProvider()
    {
        var services = Configure();

        Assert.Contains(services, d => d.ServiceType == typeof(IKeyCustodian));

        using var provider = services.BuildServiceProvider();

        // The Transit client itself serves as the external key custodian, and the provider publishes its keys.
        Assert.IsType<VaultTransitClient>(provider.GetRequiredService<IKeyCustodian>());
        Assert.IsType<ExternalKeysProvider>(provider.GetRequiredService<IAuthServiceKeysProvider>());
    }

    [Fact]
    public void ConfiguresTypedClient_WithTransitBaseAddressAndAuthHeader()
    {
        using var provider = Configure().BuildServiceProvider();

        var http = provider.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(IKeyCustodian));

        Assert.Equal("https://vault.test:8200/v1/transit/", http.BaseAddress!.ToString());
        Assert.Equal("s.test-token", Assert.Single(http.DefaultRequestHeaders.GetValues("X-Vault-Token")));
    }
}
