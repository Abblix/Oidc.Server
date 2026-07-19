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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DependencyInjection;

/// <summary>
/// Verifies the opt-in contract of the six niche endpoints. Each is off in the default
/// <see cref="OidcEndpoints.Base"/> set and turned on solely by its dedicated <c>AddX()</c> feature method,
/// which re-enables the corresponding flag via a <c>PostConfigure&lt;OidcOptions&gt;</c> and registers the endpoint
/// services. These tests lock that the flag flip happens, that it is isolated (one opt-in does not enable another),
/// and that the endpoint handler descriptors are registered.
/// </summary>
public class EndpointOptInTests
{
    private static OidcEndpoints EnabledAfter(Action<IServiceCollection> optIn)
    {
        var services = new ServiceCollection();
        optIn(services);
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptions<OidcOptions>>().Value.EnabledEndpoints;
    }

    [Fact]
    public void AddCheckSession_enables_the_CheckSession_flag()
        => Assert.True(EnabledAfter(s => s.AddCheckSession()).HasFlag(OidcEndpoints.CheckSession));

    [Fact]
    public void AddRevocation_enables_the_Revocation_flag()
        => Assert.True(EnabledAfter(s => s.AddRevocation()).HasFlag(OidcEndpoints.Revocation));

    [Fact]
    public void AddIntrospection_enables_the_Introspection_flag()
        => Assert.True(EnabledAfter(s => s.AddIntrospection()).HasFlag(OidcEndpoints.Introspection));

    [Fact]
    public void AddDynamicClientRegistration_enables_the_RegisterClient_flag()
        => Assert.True(EnabledAfter(s => s.AddDynamicClientRegistration()).HasFlag(OidcEndpoints.RegisterClient));

    [Fact]
    public void AddBackChannelAuthentication_enables_the_BackChannelAuthentication_flag()
        => Assert.True(EnabledAfter(s => s.AddBackChannelAuthentication())
            .HasFlag(OidcEndpoints.BackChannelAuthentication));

    [Fact]
    public void AddDeviceAuthorization_enables_the_DeviceAuthorization_flag()
    {
        var enabled = EnabledAfter(s =>
        {
            s.AddDeviceAuthorization();

            // The device options validator (registered by the opt-in) rejects an enabled device endpoint with no
            // settings, so supply a valid configuration; this test asserts the flag flip, not the validator.
            s.Configure<OidcOptions>(o => o.DeviceAuthorization = new DeviceAuthorizationOptions
            {
                VerificationUri = new Uri("https://provider.example/device"),
                CodeLifetime = TimeSpan.FromMinutes(15),
                PollingInterval = TimeSpan.FromSeconds(5),
                DeviceCodeLength = 32,
                UserCodeLength = 8,
            });
        });

        Assert.True(enabled.HasFlag(OidcEndpoints.DeviceAuthorization));
    }

    [Fact]
    public void Each_opt_in_enables_exactly_its_own_endpoint_on_top_of_Base()
    {
        // The result is Base plus exactly the one opted-in flag — no other opt-in endpoint leaks on.
        // (Device is covered separately because its options validator requires configured settings.)
        Assert.Equal(OidcEndpoints.Base | OidcEndpoints.CheckSession,
            EnabledAfter(s => s.AddCheckSession()));
        Assert.Equal(OidcEndpoints.Base | OidcEndpoints.Revocation,
            EnabledAfter(s => s.AddRevocation()));
        Assert.Equal(OidcEndpoints.Base | OidcEndpoints.Introspection,
            EnabledAfter(s => s.AddIntrospection()));
        Assert.Equal(OidcEndpoints.Base | OidcEndpoints.RegisterClient,
            EnabledAfter(s => s.AddDynamicClientRegistration()));
        Assert.Equal(OidcEndpoints.Base | OidcEndpoints.BackChannelAuthentication,
            EnabledAfter(s => s.AddBackChannelAuthentication()));
    }

    [Fact]
    public void AddRevocation_registers_the_revocation_handler()
    {
        var services = new ServiceCollection();
        services.AddRevocation();
        Assert.Contains(services, d => d.ServiceType == typeof(IRevocationHandler));
    }

    [Fact]
    public void AddIntrospection_registers_the_introspection_handler()
    {
        var services = new ServiceCollection();
        services.AddIntrospection();
        Assert.Contains(services, d => d.ServiceType == typeof(IIntrospectionHandler));
    }

    [Fact]
    public void AddDynamicClientRegistration_registers_the_register_client_handler()
    {
        var services = new ServiceCollection();
        services.AddDynamicClientRegistration();
        Assert.Contains(services, d => d.ServiceType == typeof(IRegisterClientHandler));
    }

    [Fact]
    public void All_opt_ins_together_enable_the_full_All_set()
    {
        // Base plus all six opt-in endpoints reconstitutes the complete OidcEndpoints.All set — the previous
        // every-endpoint-on default is exactly Base with every AddX() applied.
        var enabled = EnabledAfter(s =>
        {
            s.AddCheckSession();
            s.AddRevocation();
            s.AddIntrospection();
            s.AddDynamicClientRegistration();
            s.AddBackChannelAuthentication();
            s.AddDeviceAuthorization();
            s.Configure<OidcOptions>(o => o.DeviceAuthorization = new DeviceAuthorizationOptions
            {
                VerificationUri = new Uri("https://provider.example/device"),
                CodeLifetime = TimeSpan.FromMinutes(15),
                PollingInterval = TimeSpan.FromSeconds(5),
                DeviceCodeLength = 32,
                UserCodeLength = 8,
            });
        });

        Assert.Equal(OidcEndpoints.All, enabled);
    }

    /// <summary>
    /// Two registration modules both opting into CIBA must fail loud at the second opt-in rather than build the
    /// self-referential validator composite that deadlocks the first backchannel request. The second
    /// AddBackChannelAuthentication re-composes IBackChannelAuthenticationContextValidator, which the Compose
    /// guard now rejects. The collection is never resolved, so the latent deadlock is never reached.
    /// </summary>
    [Fact]
    public void AddBackChannelAuthentication_CalledTwice_IsRejectedInsteadOfDeadlocking()
    {
        var services = new ServiceCollection();
        services.AddBackChannelAuthentication();

        Assert.Throws<InvalidOperationException>(() => services.AddBackChannelAuthentication());
    }
}
