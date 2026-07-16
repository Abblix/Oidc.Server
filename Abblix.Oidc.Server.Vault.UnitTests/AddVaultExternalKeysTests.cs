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
using Xunit;

namespace Abblix.Oidc.Server.Vault.UnitTests;

/// <summary>
/// Verifies the wiring performed by <c>AddVaultExternalKeys</c>: the Transit client is registered as the external
/// key store behind the shared custodian and key provider, and the typed Transit client is pointed at the mount
/// with its auth header.
/// </summary>
public class AddVaultExternalKeysTests
{
    private static IServiceCollection Configure()
    {
        var services = new ServiceCollection();
        services.AddVaultExternalKeys(options =>
        {
            options.Address = "http://vault.test:8200";
            options.Token = "s.test-token";
            options.TransitMount = "transit";
            options.SigningKeyName = "oidc-sign";
            options.EncryptionKeyName = "oidc-enc";
        });
        return services;
    }

    [Fact]
    public void RegistersStoreCustodianAndKeyProvider()
    {
        var services = Configure();

        Assert.Contains(services, d => d.ServiceType == typeof(IExternalKeyStore));
        Assert.Contains(services, d =>
            d.ServiceType == typeof(IKeyCustodian) && d.ImplementationType == typeof(ExternalKeyCustodian));
        Assert.Contains(services, d => d.ServiceType == typeof(VaultTransitClient));

        using var provider = services.BuildServiceProvider();
        Assert.IsType<ExternalKeysProvider>(provider.GetRequiredService<IAuthServiceKeysProvider>());
    }

    [Fact]
    public void ConfiguresTypedClient_WithTransitBaseAddressAndAuthHeader()
    {
        using var provider = Configure().BuildServiceProvider();

        var http = provider.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(VaultTransitClient));

        Assert.Equal("http://vault.test:8200/v1/transit/", http.BaseAddress!.ToString());
        Assert.Equal("s.test-token", Assert.Single(http.DefaultRequestHeaders.GetValues("X-Vault-Token")));
    }
}
