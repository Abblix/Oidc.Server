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
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DependencyInjection;

/// <summary>
/// Locks the composed shape of the <see cref="ILogoutNotifier"/> family and the channels a provider serves.
/// Each channel is the host's own choice, made by calling
/// <see cref="Abblix.Oidc.Server.Features.ServiceCollectionExtensions.AddFrontChannelLogout"/> or
/// <see cref="Abblix.Oidc.Server.Features.ServiceCollectionExtensions.AddBackChannelLogout"/>, and both are
/// public, so the call may arrive after
/// <see cref="Abblix.Oidc.Server.Features.ServiceCollectionExtensions.AddLogoutNotification"/> has already
/// composed the family. The member must join it: landing beside the composite it would win the singular
/// resolve, and then RP-initiated logout would notify one channel while the discovery document described
/// another.
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

        // Both channels joined the member the composition always holds.
        Assert.Equal(
            [typeof(NoLogoutNotifier), typeof(BackChannelLogoutNotifier), typeof(FrontChannelLogoutNotifier)],
            services
                .Where(descriptor => descriptor.ServiceType == typeof(ILogoutNotifier) && descriptor.IsKeyedService)
                .Select(descriptor => descriptor.ResolveImplementationType()));
    }

    [Fact]
    public void AHostThatChoseNoChannel_AnswersThatItServesNone()
    {
        using var provider = BuildProvider(_ => { });
        var notifier = provider.CreateScope().ServiceProvider.GetRequiredService<ILogoutNotifier>();

        // The question is asked of a live provider rather than of the collection, because what the discovery
        // handler meets is a resolve: a family left empty would compose to nothing and throw here.
        Assert.IsType<CompositeLogoutNotifier>(notifier);
        Assert.False(notifier.FrontChannelLogoutSupported);
        Assert.False(notifier.BackChannelLogoutSupported);
    }

    [Fact]
    public void AHostThatChoseNoChannel_StillAnswersLogoutRequests()
    {
        using var provider = BuildProvider(_ => { });

        // The formatter that writes the end-session response takes the front-channel page builder whether or
        // not this host serves that channel, so the builder belongs to the machinery rather than to the
        // channel. Registered with the channel instead, a host that serves none would fail to resolve the
        // formatter - that is, answer no logout request at all - and no channel test would notice.
        var formatter = provider.CreateScope().ServiceProvider.GetRequiredService<IEndSessionResponseFormatter>();
        Assert.NotNull(formatter);
    }

    [Fact]
    public void TheBackChannelChosenAfterTheFullRegistration_IsTheOnlyChannelServed()
        => AssertOnlyTheChosenChannelIsServed(
            services => services.AddBackChannelLogout(),
            frontChannelServed: false,
            backChannelServed: true);

    [Fact]
    public void TheFrontChannelChosenAfterTheFullRegistration_IsTheOnlyChannelServed()
        => AssertOnlyTheChosenChannelIsServed(
            services => services.AddFrontChannelLogout(),
            frontChannelServed: true,
            backChannelServed: false);

    /// <summary>
    /// The host chooses one channel after the whole server is already registered. The choice has to reach the
    /// composite - the call used to be destructive, replacing it with the single notifier it registered - and
    /// it must not carry the other channel in with it.
    /// </summary>
    private static void AssertOnlyTheChosenChannelIsServed(
        Action<IServiceCollection> hostCall,
        bool frontChannelServed,
        bool backChannelServed)
    {
        using var provider = BuildProvider(hostCall);
        var notifier = provider.CreateScope().ServiceProvider.GetRequiredService<ILogoutNotifier>();

        Assert.IsType<CompositeLogoutNotifier>(notifier);
        Assert.Equal(frontChannelServed, notifier.FrontChannelLogoutSupported);
        Assert.Equal(backChannelServed, notifier.BackChannelLogoutSupported);
    }

    private static ServiceProvider BuildProvider(Action<IServiceCollection> hostCall)
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

        return services.BuildServiceProvider();
    }
}
