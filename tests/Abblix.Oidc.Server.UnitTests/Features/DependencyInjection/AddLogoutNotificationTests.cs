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
using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DependencyInjection;

/// <summary>
/// Locks the composed shape of the <see cref="ILogoutNotifier"/> family.
/// <see cref="ServiceCollectionExtensions.AddLogoutNotification"/> composes it, while
/// <see cref="ServiceCollectionExtensions.AddBackChannelLogout"/> and
/// <see cref="ServiceCollectionExtensions.AddFrontChannelLogout"/> are public and contribute a member each, so a
/// host may call one after the composition has already happened. The member must join the family: landing beside
/// the composite it would win the singular resolve, and then RP-initiated logout would notify one channel while
/// the discovery document kept advertising both.
/// </summary>
public class AddLogoutNotificationTests
{
    [Fact]
    public void ANotifierAddedAfterCompositionJoinsTheFamilyRatherThanUnseatingIt()
    {
        var services = new ServiceCollection();
        services.AddLogoutNotification();

        services.AddBackChannelLogout();
        services.AddFrontChannelLogout();

        // The composite is what the end-session endpoint and the discovery handler resolve, and it is singular,
        // so the only plain registration of the family interface must be the composite itself.
        var plain = Assert.Single(
            services, descriptor => descriptor.ServiceType == typeof(ILogoutNotifier) && !descriptor.IsKeyedService);
        Assert.Equal(typeof(CompositeLogoutNotifier), plain.ResolveImplementationType());

        // Both channels are still inside it.
        Assert.Equal(2, services.Count(
            descriptor => descriptor.ServiceType == typeof(ILogoutNotifier) && descriptor.IsKeyedService));
    }

    [Fact]
    public void AChannelAddedAfterTheFullRegistrationResolvesToTheCompositeOfBoth()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddSingleton(Mock.Of<IUserInfoProvider>());

        services.AddOidcServices(options =>
        {
            options.Issuer = TestConstants.DefaultIssuer.OriginalString;
            options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)];
        });

        // The host asks for back-channel logout explicitly, after the whole server is already registered - which
        // is redundant, since AddOidcServices registered both channels, and used to be destructive.
        services.AddBackChannelLogout();

        using var provider = services.BuildServiceProvider();
        var notifier = provider.CreateScope().ServiceProvider.GetRequiredService<ILogoutNotifier>();

        Assert.IsType<CompositeLogoutNotifier>(notifier);
        Assert.True(notifier.FrontChannelLogoutSupported);
        Assert.True(notifier.BackChannelLogoutSupported);
    }
}
