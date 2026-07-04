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
using System.Linq;
using System.Threading.Tasks;

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;

using Microsoft.Extensions.DependencyInjection;

using Moq;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DependencyInjection;

/// <summary>
/// Verifies that library extension methods honour host pre-registrations: a host that registers
/// a singular contract BEFORE calling an Abblix extension method must still have its implementation
/// win, and an enumerable strategy set must not accumulate duplicate default implementations
/// across repeated invocations.
/// </summary>
public class ServiceCollectionOverrideTests
{
    [Fact]
    public void AddAuthServiceJwt_HostPreregisteredKeysProvider_Wins()
    {
        // Issue #50 canonical example: host pre-registers IAuthServiceKeysProvider.
        var services = new ServiceCollection();
        var stub = new Mock<IAuthServiceKeysProvider>().Object;
        services.AddSingleton<IAuthServiceKeysProvider>(stub);

        services.AddAuthServiceJwt();

        var descriptors = services
            .Where(d => d.ServiceType == typeof(IAuthServiceKeysProvider))
            .ToList();

        Assert.Single(descriptors);
        Assert.Same(stub, descriptors[0].ImplementationInstance);
    }

    [Fact]
    public void AddAuthServiceJwt_InvokedTwice_DefaultsRegisteredOnce()
    {
        // TryAdd* guarantees the library's own default doesn't accumulate on repeated calls.
        var services = new ServiceCollection();

        services.AddAuthServiceJwt();
        services.AddAuthServiceJwt();

        Assert.Single(services, d => d.ServiceType == typeof(IAuthServiceKeysProvider));
        Assert.Single(services, d => d.ServiceType == typeof(IAuthServiceJwtFormatter));
        Assert.Single(services, d => d.ServiceType == typeof(IAuthServiceJwtValidator));
    }

    [Fact]
    public void AddClientAuthentication_InvokedTwice_FailsLoudInsteadOfRecomposing()
    {
        // A compose-family method composes its pipeline exactly once. Invoking it a second time would rebuild a
        // self-referential composite that deadlocks on the first resolve, so the shared Compose guard rejects the
        // second invocation loudly at registration time rather than letting the latent deadlock ship.
        var services = new ServiceCollection();

        services.AddClientAuthentication();

        var ex = Assert.Throws<InvalidOperationException>(() => services.AddClientAuthentication());
        Assert.Contains(nameof(IClientAuthenticator), ex.Message);
    }

    [Fact]
    public void AddDPoP_HostPreregisteredProofValidator_Wins()
    {
        var services = new ServiceCollection();
        var stub = new Mock<IProofValidator>().Object;
        services.AddSingleton<IProofValidator>(stub);

        services.AddDPoP();

        var descriptors = services
            .Where(d => d.ServiceType == typeof(IProofValidator))
            .ToList();

        Assert.Single(descriptors);
        Assert.Same(stub, descriptors[0].ImplementationInstance);
    }

    [Fact]
    public void AddDPoP_InvokedTwice_DefaultsRegisteredOnce()
    {
        var services = new ServiceCollection();

        services.AddDPoP();
        services.AddDPoP();

        Assert.Single(services, d => d.ServiceType == typeof(IProofValidator));
    }

    [Fact]
    public async Task AddAuthServiceJwt_HostStub_ResolvesToStub()
    {
        // End-to-end check: after the library's extension method runs, resolving the contract
        // via the provider returns the host's pre-registered instance.
        var services = new ServiceCollection();
        var stub = new Mock<IAuthServiceKeysProvider>().Object;
        services.AddSingleton<IAuthServiceKeysProvider>(stub);

        services.AddAuthServiceJwt();

        await using var provider = services.BuildServiceProvider();
        var resolved = provider.GetRequiredService<IAuthServiceKeysProvider>();

        Assert.Same(stub, resolved);
    }

    [Fact]
    public void AddOidcMinimalApi_RegistersDefaultAuthSessionService()
    {
        // The MVC transport registers AuthenticationSchemeAdapter as the default IAuthSessionService;
        // the Minimal API transport must mirror it, or a host without its own implementation fails
        // at request time on every endpoint that touches the authentication session.
        var services = new ServiceCollection();

        services.AddOidcMinimalApi();

        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IAuthSessionService));
        Assert.Equal(typeof(AuthenticationSchemeAdapter), descriptor.ImplementationType);
        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
    }

    [Fact]
    public void AddOidcMinimalApi_HostPreregisteredAuthSessionService_Wins()
    {
        var services = new ServiceCollection();
        var stub = new Mock<IAuthSessionService>().Object;
        services.AddSingleton(stub);

        services.AddOidcMinimalApi();

        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IAuthSessionService));
        Assert.Same(stub, descriptor.ImplementationInstance);
    }

    [Fact]
    public void AddOidcMinimalApi_EveryEndpointOptedIn_GraphValidates()
    {
        // The full-surface host: every optional endpoint enabled, and the only contract the host
        // itself implements is IUserInfoProvider. ValidateOnBuild constructs every registered
        // descriptor, so a missing default registration anywhere in the adapter or the core
        // fails here instead of surfacing as an HTTP 500 at request time.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRouting();
        services.AddMemoryCache();
        services.AddDistributedMemoryCache();
        services.AddAuthentication().AddCookie();
        services.AddSingleton(new Mock<IUserInfoProvider>().Object);

        // Grant-bearing opt-ins precede AddOidcMinimalApi so AddOidcCore composes their grant handlers
        services.AddDeviceAuthorization();
        services.AddBackChannelAuthentication();
        services.AddRevocation();
        services.AddIntrospection();
        services.AddCheckSession();
        services.AddDynamicClientRegistration();

        services.AddOidcMinimalApi(_ => { });
        services.AddRichAuthorizationRequests();

        using var provider = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
    }
}
