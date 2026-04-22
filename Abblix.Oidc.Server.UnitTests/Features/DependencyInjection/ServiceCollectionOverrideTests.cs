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

using System.Linq;
using System.Threading.Tasks;

using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Validation;

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
    public void AddClientAuthentication_InvokedTwice_StrategySetNotDuplicated()
    {
        // TryAddEnumerable dedupes by ImplementationType; repeated library invocation must not
        // grow the set of default IClientAuthenticator strategies.
        var services = new ServiceCollection();

        services.AddClientAuthentication();
        var firstCount = services.Count(d => d.ServiceType == typeof(IClientAuthenticator));

        services.AddClientAuthentication();
        var secondCount = services.Count(d => d.ServiceType == typeof(IClientAuthenticator));

        Assert.Equal(firstCount, secondCount);
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
}
