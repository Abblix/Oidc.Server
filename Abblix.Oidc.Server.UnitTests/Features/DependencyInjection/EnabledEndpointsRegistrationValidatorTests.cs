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

using System;
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
        services.AddOidcServices(o =>
        {
            o.Issuer = TestConstants.DefaultIssuer.OriginalString;
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
        services
            .AddCheckSession()
            .AddRevocation()
            .AddIntrospection()
            .AddDynamicClientRegistration()
            .AddBackChannelAuthentication()
            .AddDeviceAuthorization()
            .AddOidcServices(o =>
            {
                o.Issuer = TestConstants.DefaultIssuer.OriginalString;
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
