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
using Abblix.Jwt.ExternalKeys;
using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Pins that a host wiring a custodian needs nothing but this package. The placement choice is armed here, so it
/// has to be answerable here: a host that consumes JWTs without being an OpenID Provider - an SSF transmitter
/// signing security event tokens, a client protecting its own state - references this assembly and no other.
/// </summary>
/// <remarks>
/// This project references only Abblix.Jwt, which is what makes the assertion real rather than nominal: were any
/// part of the placement wiring to live in the OIDC server, these tests would not compile.
/// </remarks>
public class KeyPlacementWiringTests
{
    private static CustodianHeldKeys Keys => new() { SigningKeyName = "sign" };

    private static IServiceCollection WithCustodian()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new Mock<IKeyCustodian>(MockBehavior.Loose).Object);
        return services;
    }

    private static JsonWebKey PublicOnlyKey()
    {
        using var rsa = RSA.Create(2048);
        return new RsaJsonWebKey { KeyId = "sign" }.Apply(rsa.ExportParameters(false));
    }

    [Fact]
    public void StartupValidationPasses_WhenAJwtOnlyHostChoosesAPlacement()
    {
        var services = WithCustodian();
        services.AddJsonWebTokens();
        services.RequireKeyPlacement().UseKeysInCustodian(Keys);

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IStartupValidator>().Validate();
    }

    [Fact]
    public void StartupValidationFails_WhenNoPlacementIsChosen()
    {
        var services = WithCustodian();
        services.AddJsonWebTokens();
        services.RequireKeyPlacement();

        using var provider = services.BuildServiceProvider();

        var error = Assert.Throws<OptionsValidationException>(
            provider.GetRequiredService<IStartupValidator>().Validate);

        // The message must name a call the host can actually write. Asserting a substring of a message is only
        // worth anything when the substring is the method name, which the compiler then keeps honest.
        Assert.Contains(
            nameof(ExternalKeysServiceCollectionExtensions.UseKeysInCustodian),
            Assert.Single(error.Failures));
    }

    [Fact]
    public void ExternalSignerOwnsAPublicOnlyKey_WhenThePlacementFollowsTheJwtRegistration()
    {
        var services = WithCustodian();
        services.AddJsonWebTokens();
        services.RequireKeyPlacement().UseKeysInCustodian(Keys);

        using var provider = services.BuildServiceProvider();

        // A public-only key is the signal that routes signing to the custodian, so the composed seam must own it.
        // The in-process signer alone would not, having no private material to sign with.
        Assert.True(provider.GetRequiredService<IDataSigner>().CanSign(PublicOnlyKey()));
    }

    [Fact]
    public void PlacementFailsFast_WhenItRunsBeforeTheJwtRegistration()
    {
        var services = WithCustodian();

        var error = Assert.Throws<InvalidOperationException>(
            () => services.RequireKeyPlacement().UseKeysInCustodian(Keys));

        Assert.Contains(nameof(ServiceCollectionExtensions.AddJsonWebTokens), error.Message);
    }

    [Fact]
    public void CustodianIsDiConstructed_WhenRegisteredByType()
    {
        var services = new ServiceCollection();
        services.AddJsonWebTokens();
        services.AddCustodian<StubCustodian>().UseKeysInCustodian(Keys);

        using var provider = services.BuildServiceProvider();

        // The type overload exists so a custodian may depend on the host's own services, which is only true if the
        // container builds it rather than the caller.
        Assert.IsType<StubCustodian>(provider.GetRequiredService<IKeyCustodian>());
        provider.GetRequiredService<IStartupValidator>().Validate();
    }

    /// <summary>
    /// A custodian that answers nothing: these tests are about the wiring, and no key operation is reached.
    /// </summary>
    private sealed class StubCustodian : IKeyCustodian
    {
        public Task<byte[]> SignAsync(
            string keyId, string algorithm, byte[] data, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<byte[]?> UnwrapKeyAsync(
            string keyId,
            string algorithm,
            JsonWebTokenHeader header,
            byte[] encryptedKey,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<byte[]> AgreeKeyAsync(
            string keyId, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public IAsyncEnumerable<KeyVersion> GetKeyVersionsAsync(
            string keyName, CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    [Fact]
    public void TheChosenKeysAreResolvable_SoAHostCanPublishThemItself()
    {
        var services = WithCustodian();
        services.AddJsonWebTokens();
        services.RequireKeyPlacement().UseKeysInCustodian(Keys);

        using var provider = services.BuildServiceProvider();

        // What a JWT-only host does with the placement: it asks which keys were named, enumerates their versions
        // through the custodian, and hands the public half to whatever signs. Without this registration the
        // selection would be visible only to the OIDC server's key provider.
        Assert.Equal("sign", provider.GetRequiredService<CustodianHeldKeys>().SigningKeyName);
    }

    [Fact]
    public void MintingPlacementRefusesWithoutAStore_BecauseAnUnsharedRingFailsOnFirstUse()
    {
        var services = WithCustodian();
        services.AddJsonWebTokens();
        services.RequireKeyPlacement().UseKeysInProcess(new MintedKeys { KeyEncryptionKeyName = "kek" });

        using var provider = services.BuildServiceProvider();

        var error = Assert.Throws<OptionsValidationException>(
            provider.GetRequiredService<IStartupValidator>().Validate);

        Assert.Contains("PersistRingTo", Assert.Single(error.Failures));
    }
}
