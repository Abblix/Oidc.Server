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
using System.Security.Cryptography;
using Abblix.Jwt;
using Abblix.Jwt.Signing;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ExternalKeys;

/// <summary>
/// Pins the wiring contract every custodian shares, against a stub one, since none of it depends on which
/// custodian is registered: the placement choice is enforced at startup, the key provider guards a resolve until the
/// choice arrives, and the placement call must follow the OIDC registration.
/// </summary>
/// <remarks>
/// The ordering is the subtle one. The placement call composes the external crypto backends with their in-process
/// peers, so those peers must already be registered: run first, it finds a one-member family, composes nothing,
/// and the external backend then loses the singular resolve to the local one that arrives after it. Nothing
/// detects that at runtime - the signing seam simply reports it cannot sign a key it should have routed to the
/// custodian - so it is asserted here.
/// </remarks>
public class ExternalKeysWiringTests
{
    private static JsonWebKey PublicOnlyKey()
    {
        using var rsa = RSA.Create(2048);
        return new RsaJsonWebKey { KeyId = "oidc-sign" }.Apply(rsa.ExportParameters(false));
    }

    private static IServiceCollection WithCustodian(IServiceCollection services)
    {
        services.AddSingleton(new Mock<IKeyCustodian>(MockBehavior.Loose).Object);
        return services;
    }

    private static CustodianHeldKeys Keys => new() { SigningKeyName = "oidc-sign" };

    [Fact]
    public void ExternalSignerOwnsAPublicOnlyKey_WhenTheTierCallFollowsTheOidcRegistration()
    {
        var services = WithCustodian(new ServiceCollection());
        services.AddJsonWebTokens();
        services.AddCustodian().UseKeysInCustodian(Keys);

        using var provider = services.BuildServiceProvider();

        // A public-only key is the signal that routes signing to the custodian, so the composed seam must own it.
        // The in-process signer alone would not, having no private material to sign with.
        Assert.True(provider.GetRequiredService<IDataSigner>().CanSign(PublicOnlyKey()));
    }

    [Fact]
    public void TierCallFailsFast_WhenItRunsBeforeTheOidcRegistration()
    {
        var services = WithCustodian(new ServiceCollection());

        // The mistake: the placement call has no in-process peer to compose with yet.
        var error = Assert.Throws<InvalidOperationException>(
            () => services.AddCustodian().UseKeysInCustodian(Keys));

        Assert.Contains("AddOidcServices", error.Message);
    }

    [Fact]
    public void StartupValidationFails_WhenTheTierIsNeverChosen()
    {
        var services = WithCustodian(new ServiceCollection());
        services.AddJsonWebTokens();
        services.AddCustodian();

        using var provider = services.BuildServiceProvider();

        // The host runs the startup validators before it starts the hosted service that opens the HTTP port, so
        // this is the failure a misconfigured deployment actually meets: no port, no token, and no silent
        // fallback to the static keys of OidcOptions.
        var error = Assert.Throws<OptionsValidationException>(
            provider.GetRequiredService<IStartupValidator>().Validate);

        // The message names the calls that exist. It used to name "HoldKeysIn...", which never did, and this
        // assertion is what pinned the mistake in place: a message nobody can act on reads as a correct
        // message to a test that only checks a substring.
        Assert.Contains(
            nameof(Server.Features.ExternalKeys.ServiceCollectionExtensions.UseKeysInCustodian),
            Assert.Single(error.Failures));
    }

    [Fact]
    public void StartupValidationPasses_WhenTheTierIsChosen()
    {
        var services = WithCustodian(new ServiceCollection());
        services.AddJsonWebTokens();
        services.AddCustodian().UseKeysInCustodian(Keys);

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IStartupValidator>().Validate();
    }

    [Fact]
    public void KeyProviderStillGuards_WhenTheTierIsNeverChosen()
    {
        var services = WithCustodian(new ServiceCollection());
        services.AddJsonWebTokens();
        services.AddCustodian();

        using var provider = services.BuildServiceProvider();
        var keysProvider = provider.GetRequiredService<IAuthServiceKeysProvider>();

        // The second line, for a host that resolves keys with no host lifetime to run the startup validation.
        var error = Assert.Throws<InvalidOperationException>(() => keysProvider.GetSigningKeys());

        Assert.Contains("HoldKeysIn", error.Message);
    }
}
