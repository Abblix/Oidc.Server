// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DependencyInjection;

/// <summary>
/// Locks the startup cross-check between <see cref="OidcOptions.EnabledEndpoints"/> and the opt-in feature
/// registrations: advertising an opt-in endpoint without calling its <c>AddX()</c> must fail fast at options
/// resolution (naming the endpoint) rather than 500 on every request to the unregistered handler.
/// </summary>
public class EnabledEndpointsRegistrationValidatorTests
{
    [Fact]
    public void AllWithoutOptIns_FailsFast_NamingTheUnregisteredEndpoint()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddOidcServices(o =>
        {
            o.Tenants.Add(new TenantDefinition { Id = TestIssuer.TenantId, Issuer = TestConstants.DefaultIssuer });
            o.EnabledEndpoints = OidcEndpoints.All;
        });

        using var provider = services.BuildServiceProvider();

        var ex = Assert.Throws<OptionsValidationException>(
            () => _ = provider.GetRequiredService<IOptions<OidcOptions>>().Value);

        Assert.Contains(nameof(OidcEndpoints.Revocation), ex.Message);
    }

    [Fact]
    public void AllWithEveryOptIn_Validates()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services
            .AddCheckSession()
            .AddRevocation()
            .AddIntrospection()
            .AddDynamicClientRegistration()
            .AddBackChannelAuthentication()
            .AddDeviceAuthorization()
            .AddOidcServices(o =>
            {
                // A signing key, because a tenant with none is refused at startup by TenantKeysCheck and this test
                // is about endpoint registration.
                o.Tenants.Add(new TenantDefinition
                {
                    Id = TestIssuer.TenantId,
                    Issuer = TestConstants.DefaultIssuer,
                    SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
                });
                o.DeviceAuthorization = new DeviceAuthorizationOptions
                {
                    VerificationUri = new Uri("https://provider.example/device"),
                    CodeLifetime = TimeSpan.FromMinutes(15),
                    PollingInterval = TimeSpan.FromSeconds(5),
                    DeviceCodeLength = 32,
                    UserCodeLength = 8,
                };
            });

        using var provider = services.BuildServiceProvider();
        var value = provider.GetRequiredService<IOptions<OidcOptions>>().Value;

        Assert.Equal(OidcEndpoints.All, value.EnabledEndpoints);
    }
}
