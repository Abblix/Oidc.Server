// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
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
    public void BackChannelAddedAfterTheFullRegistrationLeavesBothChannelsServed()
        => AssertBothChannelsSurvive(services => services.AddBackChannelLogout());

    [Fact]
    public void FrontChannelAddedAfterTheFullRegistrationLeavesBothChannelsServed()
        => AssertBothChannelsSurvive(services => services.AddFrontChannelLogout());

    /// <summary>
    /// The host asks for one channel explicitly after the whole server is already registered. The call is
    /// redundant - AddOidcServices registered both - and it used to be destructive, replacing the composite
    /// with the single notifier it re-registered.
    /// </summary>
    private static void AssertBothChannelsSurvive(Action<IServiceCollection> hostCall)
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

        hostCall(services);

        using var provider = services.BuildServiceProvider();
        var notifier = provider.CreateScope().ServiceProvider.GetRequiredService<ILogoutNotifier>();

        Assert.IsType<CompositeLogoutNotifier>(notifier);
        Assert.True(notifier.FrontChannelLogoutSupported);
        Assert.True(notifier.BackChannelLogoutSupported);
    }
}
