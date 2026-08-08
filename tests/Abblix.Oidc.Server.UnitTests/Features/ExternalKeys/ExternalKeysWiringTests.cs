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
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ExternalKeys;

/// <summary>
/// Pins the one part of external key custody that IS this server's own: which key provider answers, given where the
/// host put its private halves. Everything else about the wiring - the placement choice, the guard that a custodian
/// without one trips, the ordering against the crypto registration - belongs to Abblix.Jwt and is asserted there,
/// once, against a stub custodian.
/// </summary>
/// <remarks>
/// The selection is read at resolve rather than written at registration, which is what frees the placement call from
/// having to run after this server's own. So each case here builds the container in a different order on purpose.
/// </remarks>
public class ExternalKeysWiringTests
{
    private static CustodianHeldKeys Keys => new() { SigningKeyName = "oidc-sign" };

    private static IServiceCollection AnOidcHost()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new Mock<IKeyCustodian>(MockBehavior.Loose).Object);
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddSingleton(TimeProvider.System);
        services.AddJsonWebTokens();
        services.AddAuthServiceJwt();
        return services;
    }

    [Fact]
    public void CustodianHeldPlacementIsServedByTheExternalProvider()
    {
        var services = AnOidcHost();
        services.RequireKeyPlacement().UseKeysInCustodian(Keys);

        using var provider = services.BuildServiceProvider();

        Assert.IsType<ExternalKeysProvider>(provider.GetRequiredService<IAuthServiceKeysProvider>());
    }

    [Fact]
    public void MintingPlacementIsServedByTheMintedProvider()
    {
        var services = AnOidcHost();
        services.RequireKeyPlacement().UseKeysInProcess(new MintedKeys { KeyEncryptionKeyName = "oidc-kek" });
        services.AddSingleton(new Mock<IKeyRingStore>(MockBehavior.Loose).Object);

        using var provider = services.BuildServiceProvider();

        Assert.IsType<MintedKeysProvider>(provider.GetRequiredService<IAuthServiceKeysProvider>());
    }

    [Fact]
    public void PlacementChosenBeforeTheServerRegistration_IsStillServed()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new Mock<IKeyCustodian>(MockBehavior.Loose).Object);
        services.AddOptions<OidcOptions>();
        services.AddSingleton(TimeProvider.System);
        services.AddJsonWebTokens();

        // Before AddAuthServiceJwt, which is the ordering the crypto composition permits and the old registration
        // did not: it replaced the provider at the placement call, so the server's own TryAdd afterwards was a
        // no-op only by luck of ordering.
        services.RequireKeyPlacement().UseKeysInCustodian(Keys);
        services.AddAuthServiceJwt();

        using var provider = services.BuildServiceProvider();

        Assert.IsType<ExternalKeysProvider>(provider.GetRequiredService<IAuthServiceKeysProvider>());
    }

    [Fact]
    public void HostRegistrationStillWins_WhenItBringsItsOwnProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new Mock<IKeyCustodian>(MockBehavior.Loose).Object);
        services.AddSingleton(Mock.Of<IAuthServiceKeysProvider>());
        services.AddOptions<OidcOptions>();
        services.AddSingleton(TimeProvider.System);
        services.AddJsonWebTokens();
        services.AddAuthServiceJwt();
        services.RequireKeyPlacement().UseKeysInCustodian(Keys);

        using var provider = services.BuildServiceProvider();

        // The placement decides which provider the LIBRARY would install, never that one must be installed: a host
        // layering its own provider over the placement's is the documented way to cache the custodian's key list.
        Assert.IsNotType<ExternalKeysProvider>(provider.GetRequiredService<IAuthServiceKeysProvider>());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConfiguredKeysAreRefused_WhenACustodianIsRegisteredAndNoPlacementChosen(bool signing)
    {
        var services = AnOidcHost();

        using var provider = services.BuildServiceProvider();
        var keysProvider = provider.GetRequiredService<IAuthServiceKeysProvider>();

        Assert.IsType<OidcOptionsKeysProvider>(keysProvider);

        // Both roles, because both fail the same silent way: the host believes its private halves are in the
        // custodian and they are in a settings file, with nothing anywhere saying so.
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await (signing ? keysProvider.GetSigningKeys() : keysProvider.GetEncryptionKeys())
                .ToListAsync(TestContext.Current.CancellationToken));

        Assert.Contains(nameof(ExternalKeysServiceCollectionExtensions.UseKeysInCustodian), error.Message);
    }

    [Fact]
    public async Task ConfiguredKeysAreServed_WhenNoCustodianIsRegisteredAtAll()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddSingleton(TimeProvider.System);
        services.AddJsonWebTokens();
        services.AddAuthServiceJwt();

        using var provider = services.BuildServiceProvider();
        var keysProvider = provider.GetRequiredService<IAuthServiceKeysProvider>();

        // The refusal is about a HALF-wired custodian, so a host that wired none must be unaffected by it.
        Assert.Empty(await keysProvider.GetSigningKeys().ToListAsync(TestContext.Current.CancellationToken));
    }
}
