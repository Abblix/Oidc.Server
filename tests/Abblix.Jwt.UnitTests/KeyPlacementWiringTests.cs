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
using Abblix.DependencyInjection;
using Abblix.Jwt.ExternalKeys;
using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Pins that a host wiring a custodian needs nothing but this package. The placement choice is armed here, so it
/// has to be answerable here: a host that consumes JWTs without being an OpenID Provider - a transmitter signing
/// security event tokens, a client protecting its own state - references this assembly and no other.
/// </summary>
/// <remarks>
/// This project references only Abblix.Jwt, which is what makes the assertion real rather than nominal: were any
/// part of the placement wiring to live in the OIDC server, these tests would not compile. That guarantee rests on
/// the project file, so adding a reference to Abblix.Oidc.Server for some unrelated test would retire it silently.
/// </remarks>
public class KeyPlacementWiringTests
{
    private const string SigningKeyName = "sign";

    private static CustodianHeldKeys Keys => new() { SigningKeyName = SigningKeyName };

    private static IServiceCollection WithCustodian()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new Mock<IKeyCustodian>(MockBehavior.Loose).Object);
        return services;
    }

    private static JsonWebKey PrivateBearingKey()
    {
        using var rsa = RSA.Create(2048);
        return new RsaJsonWebKey { KeyId = SigningKeyName }.Apply(rsa.ExportParameters(true));
    }

    private static JsonWebKey PublicOnlyKey()
    {
        using var rsa = RSA.Create(2048);
        return new RsaJsonWebKey { KeyId = SigningKeyName }.Apply(rsa.ExportParameters(false));
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

    [Theory]
    [InlineData(KeyPlacement.Custodian)]
    [InlineData(KeyPlacement.InProcess)]
    public void EachPlacementIsRecorded_AndSatisfiesTheGuard(KeyPlacement placement)
    {
        var services = WithCustodian();
        services.AddJsonWebTokens();

        if (placement == KeyPlacement.Custodian)
            services.RequireKeyPlacement().UseKeysInCustodian(Keys);
        else
            services
                .RequireKeyPlacement()
                .UseKeysInProcess(new MintedKeys { KeyEncryptionKeyName = "kek" })
                .Services.AddSingleton(Mock.Of<IKeyRingStore>());

        using var provider = services.BuildServiceProvider();

        // The recorded value, not merely "something was recorded": a consumer dispatches on it, so the two
        // placements must be distinguishable and this suite is where the enum's own name is held to the wiring.
        Assert.Equal(
            placement,
            provider.GetRequiredService<IOptions<KeyPlacementChoice>>().Value.ChosenPlacement);

        // And the positive branch of every startup validator both placements arm, which a refusal test cannot reach.
        provider.GetRequiredService<IStartupValidator>().Validate();
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
    public void CompositionSurvivesALaterJwtRegistration()
    {
        var services = WithCustodian();
        services.AddJsonWebTokens();
        services.RequireKeyPlacement().UseKeysInCustodian(Keys);

        // Not a mistake a host can be told to avoid: the OIDC registration performs AddJsonWebTokens, and so does
        // the security-event one, so anything registered after a placement must not be able to unseat the composed
        // seam. It could: TryAddEnumerable dedupes against plain descriptors and a composed family is keyed, so the
        // local backend landed a second time beside the composite and won the singular resolve, in silence.
        services.AddJsonWebTokens();

        using var provider = services.BuildServiceProvider();

        Assert.True(provider.GetRequiredService<IDataSigner>().CanSign(PublicOnlyKey()));
        Assert.IsType<CompositeSigner>(provider.GetRequiredService<IDataSigner>());
    }

    [Fact]
    public void APlacementWithNoCustodianIsRefused()
    {
        var services = new ServiceCollection();
        services.AddJsonWebTokens();

        // Half a sentence: a placement says where a CUSTODIAN's keys live. Recorded rather than refused, it passes
        // startup validation - the choice looks made - and dies on the first key operation as the container's own
        // "unable to resolve IKeyCustodian", naming neither this call nor the registration that is missing.
        var error = Assert.Throws<InvalidOperationException>(
            () => services.RequireKeyPlacement().UseKeysInCustodian(Keys));

        Assert.Contains(nameof(IKeyCustodian), error.Message);
    }

    [Theory]
    [InlineData(ServiceLifetime.Scoped)]
    [InlineData(ServiceLifetime.Transient)]
    public void ACustodianShorterLivedThanItsCallersIsRefused(ServiceLifetime lifetime)
    {
        var services = new ServiceCollection();
        services.AddJsonWebTokens();
        services.Add(new ServiceDescriptor(typeof(IKeyCustodian), typeof(StubCustodian), lifetime));

        // The backends reaching the custodian are singletons. ValidateScopes would catch the scoped case in
        // Development and nothing would catch either in Production, so the registration call refuses instead.
        var error = Assert.Throws<InvalidOperationException>(
            () => services.RequireKeyPlacement().UseKeysInCustodian(Keys));

        Assert.Contains(nameof(ServiceLifetime.Singleton), error.Message);
        Assert.Contains(lifetime.ToString(), error.Message);
    }

    [Fact]
    public void HostPreRegisteredCustodianWins()
    {
        var chosen = new StubCustodian();

        var services = new ServiceCollection();
        services.AddJsonWebTokens();
        services.AddSingleton<IKeyCustodian>(chosen);
        services.AddCustodian<DependentCustodian>().UseKeysInCustodian(Keys);

        using var provider = services.BuildServiceProvider();

        // The library never beats a host that already chose, which is what TryAdd in AddCustodian is for.
        Assert.Same(chosen, provider.GetRequiredService<IKeyCustodian>());
    }

    [Fact]
    public void AKeyedSignerOfTheHostIsNotTheSigningFamily()
    {
        var services = new ServiceCollection();

        // A host may keep a signer of its own under a key it resolves by name. That is neither a member of the
        // signing family nor a composition of it, so the JWT registration must not read it as either - taken for
        // a composition it aborts the whole registration, taken for a member it withholds the local backend and
        // leaves nothing to sign with.
        services.AddKeyedSingleton<IDataSigner, HostSigner>("hsm");

        services.AddJsonWebTokens();

        using var provider = services.BuildServiceProvider();

        Assert.IsType<LocalKeySigner>(provider.GetRequiredService<IDataSigner>());
        Assert.IsType<HostSigner>(provider.GetRequiredKeyedService<IDataSigner>("hsm"));
    }

    [Fact]
    public void ALocalBackendJoinsAFamilyTheHostComposedItself()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new Mock<IKeyCustodian>(MockBehavior.Loose).Object);

        // A host may bring its own IDataSigner and compose the family under its own composite. The local backend
        // must still end up INSIDE that family: added beside it, it would win the singular resolve; skipped
        // entirely, nothing would sign a key that carries its private half.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IDataSigner, HostSigner>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IDataSigner, ExternalKeySigner>());
        services.Compose<IDataSigner, CompositeSigner>();

        services.AddJsonWebTokens();

        using var provider = services.BuildServiceProvider();
        var signer = provider.GetRequiredService<IDataSigner>();

        Assert.IsType<CompositeSigner>(signer);
        Assert.True(signer.CanSign(PublicOnlyKey()));
        Assert.True(signer.CanSign(PrivateBearingKey()));
    }

    [Fact]
    public void CustodianIsDiConstructed_WhenRegisteredByType()
    {
        var services = new ServiceCollection();
        services.AddJsonWebTokens();
        services.AddSingleton(TimeProvider.System);
        services.AddCustodian<DependentCustodian>().UseKeysInCustodian(Keys);

        // ValidateScopes, so this also asserts nothing on the placement's path captures a scope.
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        // The type overload exists so a custodian may depend on the host's own services, which is only true if the
        // container builds it. A parameterless stub could not tell the two apart, so this one takes a dependency
        // and the assertion is that the container supplied it.
        var custodian = Assert.IsType<DependentCustodian>(provider.GetRequiredService<IKeyCustodian>());
        Assert.Same(provider.GetRequiredService<TimeProvider>(), custodian.TimeProvider);

        provider.GetRequiredService<IStartupValidator>().Validate();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TheChosenKeysAreResolvable_SoAHostCanPublishThemItself(bool fromFactory)
    {
        var services = WithCustodian();
        services.AddJsonWebTokens();

        var builder = services.RequireKeyPlacement();

        // Both overloads must leave the same shape behind. The factory one relies on overload resolution picking
        // ServiceDescriptor.Singleton's FACTORY overload over its instance one - pick the instance overload and the
        // container would hold a delegate under its own type, with CustodianHeldKeys resolving to nothing.
        if (fromFactory)
            builder.UseKeysInCustodian(_ => Keys);
        else
            builder.UseKeysInCustodian(Keys);

        using var provider = services.BuildServiceProvider();

        // What a JWT-only host does with the placement: it asks which keys were named, enumerates their versions
        // through the custodian, and hands the public half to whatever signs. Without this registration the
        // selection would be visible only to the OIDC server's key provider.
        Assert.Equal(SigningKeyName, provider.GetRequiredService<CustodianHeldKeys>().SigningKeyName);
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

        Assert.Contains(nameof(IKeyRingStore), Assert.Single(error.Failures));
    }

    /// <summary>
    /// A custodian that answers nothing and takes one dependency: these tests are about the wiring, and no key
    /// operation is reached. The dependency is what makes DI construction observable.
    /// </summary>
    private sealed class DependentCustodian(TimeProvider timeProvider) : StubCustodian
    {
        public TimeProvider TimeProvider { get; } = timeProvider;
    }

    private sealed class HostSigner : IDataSigner
    {
        public bool CanSign(JsonWebKey key) => false;

        public Task<byte[]> SignAsync(
            JsonWebKey key, string algorithm, byte[] data, CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    private class StubCustodian : IKeyCustodian
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
}
