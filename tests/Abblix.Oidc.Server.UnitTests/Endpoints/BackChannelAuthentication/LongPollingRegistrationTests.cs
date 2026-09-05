// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication;

/// <summary>
/// What the container hands back for the long-polling service when long polling is switched off, which is how
/// every host starts out.
/// </summary>
public class LongPollingRegistrationTests
{
    /// <summary>
    /// The service resolves to a real instance whether or not the feature is switched on.
    /// </summary>
    /// <remarks>
    /// The registration used to be a factory that returned null on this path, and a factory answering null
    /// publishes a false non-null through the container. Nothing in the type system marks the contract as
    /// nullable, so a consumer that resolves it normally receives the null it was told could not be there; an
    /// enumeration of the contract yields a null element; and <c>GetRequiredService</c> reports the service as
    /// unregistered while a descriptor for it plainly exists, which sends the reader looking for a missing
    /// registration that is right in front of them. Constructing the object when it will not be used costs one
    /// allocation at startup.
    /// The switch is read at request time by the grant handler, so this test also pins the two facts that make
    /// the situation reachable rather than hypothetical: the switch defaults to off, and resolution succeeds
    /// anyway.
    /// </remarks>
    [Fact]
    public void TheLongPollingServiceResolvesWhileTheFeatureIsOff()
    {
        var provider = BuildProvider();

        var options = provider.GetRequiredService<IOptions<OidcOptions>>();
        Assert.False(options.Value.BackChannelAuthentication.UseLongPolling);

        Assert.NotNull(provider.GetService<IBackChannelLongPollingService>());
        Assert.NotNull(provider.GetRequiredService<IBackChannelLongPollingService>());
    }

    private static IServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();

        // Host-level prerequisites every real ASP.NET host registers: memory-backed caches for the storages,
        // and stubs for the host-supplied services the CIBA registration transitively touches.
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddSingleton(Mock.Of<IUserCredentialsAuthenticator>());
        services.AddSingleton(Mock.Of<IUserInfoProvider>());

        // CIBA is opt-in and carries a grant handler, so it registers before AddOidcServices composes them.
        // UseLongPolling is left at its default, which is the state under test.
        services.AddBackChannelAuthentication();

        services.AddOidcServices(options =>
        {
            options.Issuer = TestConstants.DefaultIssuer.OriginalString;
            options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)];
            options.RequireInitialAccessToken = false;
        });

        return services.BuildServiceProvider();
    }
}
