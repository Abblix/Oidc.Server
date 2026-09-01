// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// The transmitter-to-receiver round trip over the REAL cryptography of the JWT core: a token
/// built, signed with a generated RSA key, and validated through the default pipeline with the
/// matching public key. Nothing here is faked, which is what makes a green run evidence that the
/// package and the core actually compose.
/// </summary>
public class InfrastructureIntegrationTests
{
    private const string Issuer = "https://tenant.example.com";
    private const string Audience = "https://receiver.example.com/events";
    private const string MembershipChanged = "https://tenant.example.com/events/membership-changed";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    /// <summary>
    /// The discovery entry point turns the option on and still lets the caller configure the rest,
    /// including turning it back off - the delegate runs last on purpose, so a host is never left
    /// arguing with its own registration.
    /// </summary>
    [Fact]
    public void AddDiscoveryKeyResolution_TurnsTheOptionOn_AndTheCallerStillHasTheLastWord()
    {
        var services = new ServiceCollection();
        services.AddDiscoveryKeyResolution(options => options.CacheLifetime = TimeSpan.FromMinutes(3));

        using (var provider = services.BuildServiceProvider())
        {
            var options = provider.GetRequiredService<IOptions<JwksKeyResolutionOptions>>().Value;
            Assert.True(options.UseDiscoveryDocument);
            Assert.Equal(TimeSpan.FromMinutes(3), options.CacheLifetime);
            Assert.IsType<JwksIssuerKeyResolver>(provider.GetRequiredService<IIssuerKeyResolver>());
        }

        // Reading the four lines of the extension would not show which of the two writes wins.
        var overriding = new ServiceCollection();
        overriding.AddDiscoveryKeyResolution(options => options.UseDiscoveryDocument = false);

        using var overridden = overriding.BuildServiceProvider();
        Assert.False(overridden.GetRequiredService<IOptions<JwksKeyResolutionOptions>>()
            .Value.UseDiscoveryDocument);
    }

    [Fact]
    public void AddJwksKeyResolution_IsSelfSufficient_AndHonorsAHostPreRegistration()
    {
        // The extension owes its resolver every dependency it needs; constructing through the
        // container is the proof of that, where reading the registration list is not.
        var services = new ServiceCollection();
        services.AddJwksKeyResolution(options => options.CacheLifetime = TimeSpan.FromMinutes(5));

        using (var provider = services.BuildServiceProvider())
        {
            Assert.IsType<JwksIssuerKeyResolver>(provider.GetRequiredService<IIssuerKeyResolver>());
            Assert.Equal(
                TimeSpan.FromMinutes(5),
                provider.GetRequiredService<IOptions<JwksKeyResolutionOptions>>().Value.CacheLifetime);
        }

        // TryAdd semantics: a host that already chose its resolver keeps it, whatever the order.
        var preConfigured = new ServiceCollection();
        var chosen = new FixedKeyResolver();
        preConfigured.AddSingleton<IIssuerKeyResolver>(chosen);
        preConfigured.AddJwksKeyResolution();

        using var preProvider = preConfigured.BuildServiceProvider();
        Assert.Same(chosen, preProvider.GetRequiredService<IIssuerKeyResolver>());
    }

    /// <summary>
    /// A resolver over a fixed key set - the deployment-knowledge seam, which a test supplies
    /// directly instead of fetching a JWKS document.
    /// </summary>
    private sealed class FixedKeyResolver(params JsonWebKey[] keys) : IIssuerKeyResolver
    {
        public async IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
            string issuer,
            string? keyId = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            foreach (var key in keys)
            {
                yield return key;
            }
        }
    }

    private static ServiceProvider BuildHost(JsonWebKey signingKey, JsonWebKey verificationKey)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.AddSingleton<IIssuerKeyResolver>(new FixedKeyResolver(verificationKey));
        services.AddSecurityEvents(options =>
        {
            options.SigningKeySource = _ => Task.FromResult(signingKey);
        });

        services.AddSecurityEventValidationProfile("test", profile => profile.UseDefaultPipeline());

        return services.BuildServiceProvider();
    }

    private static async Task<string> SignedCompact(IServiceProvider provider)
        => await new SecurityEventTokenBuilder()
            .WithIssuer(Issuer)
            .WithJwtId("jti-1")
            .WithIssuedAt(Now)
            .WithAudience(Audience)
            .WithEvent(MembershipChanged, new JsonObject { ["change"] = "revoked" })
            .SignAsync(
                provider.GetRequiredService<ISecurityEventTokenSigner>(),
                TestContext.Current.CancellationToken);

    private static SecurityEventTokenValidationOptions ReceiverOptions() => new()
    {
        ExpectedAudience = Audience,
        ExpectedIssuers = [Issuer],
    };

    [Fact]
    public async Task SignedToken_RoundTrips_ThroughTheDefaultPipeline()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        await using var host = BuildHost(key, key);

        var compact = await SignedCompact(host);

        var result = await host.GetRequiredKeyedService<ISecurityEventTokenValidator>("test")
            .ValidateAsync(compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated), "Validation unexpectedly failed.");
        Assert.Equal(Issuer, validated.Token.Issuer);
        Assert.Equal(SecurityEventToken.TokenType, validated.Token.Token.Header.Type);
        Assert.NotNull(validated.EventPayloads);
        Assert.IsType<UnknownEventPayload>(validated.EventPayloads[MembershipChanged]);
    }

    [Fact]
    public async Task TamperedToken_IsRejected_AsSignatureInvalid()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        await using var host = BuildHost(key, key);

        var compact = await SignedCompact(host);

        // One byte of the payload changes; the signature covered the original bytes.
        var segments = compact.Split('.');
        var tampered = $"{segments[0]}.{segments[1][..^2]}AA.{segments[2]}";

        var result = await host.GetRequiredKeyedService<ISecurityEventTokenValidator>("test")
            .ValidateAsync(tampered, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.True(
            error.Code is SecurityEventTokenErrorCode.SignatureInvalid
                or SecurityEventTokenErrorCode.MalformedToken,
            $"A tampered token must die on signature or parsing, not {error.Code}.");
    }

    [Fact]
    public async Task WrongVerificationKey_IsRejected_AsSignatureInvalid()
    {
        var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var unrelatedKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        await using var host = BuildHost(signingKey, unrelatedKey);

        var compact = await SignedCompact(host);

        var result = await host.GetRequiredKeyedService<ISecurityEventTokenValidator>("test")
            .ValidateAsync(compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.SignatureInvalid, error.Code);
    }

    /// <summary>
    /// A validly signed token whose JOSE header is structurally wrong is a MALFORMED token, not a key
    /// problem.
    /// </summary>
    /// <remarks>
    /// The signature verifies and the algorithm is accepted, so neither thing
    /// <see cref="SecurityEventTokenErrorCode.SignatureInvalid"/> stands for happened - and on the wire
    /// that code is <c>invalid_key</c>, which told a transmitter its keys were unacceptable over a
    /// header it should have been told to fix. <c>crit</c> is checked unconditionally, right after the
    /// signature, so this is reachable by any transmitter that emits one.
    /// <para>
    /// The core reports it as <see cref="JwtError.InvalidHeader"/>, which is what that member's own
    /// documentation describes - "the crit array is malformed or names an unknown extension" - and the
    /// mapping here carries the distinction the rest of the way.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AStructurallyBadCriticalHeader_IsRejected_AsMalformedToken()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        await using var host = BuildHost(key, key);

        var built = new SecurityEventTokenBuilder()
            .WithIssuer(Issuer)
            .WithJwtId("jti-crit")
            .WithIssuedAt(Now)
            .WithAudience(Audience)
            .WithEvent(MembershipChanged, new JsonObject { ["change"] = "revoked" })
            .Build();

        // Signed OVER the bad header, so the token is genuine and only its structure is wrong. A header
        // edited after signing would fail on the signature instead and prove nothing.
        built.Token.Header.Critical = ["not-a-real-header"];

        var compact = await host.GetRequiredService<ISecurityEventTokenSigner>()
            .SignAsync(built, TestContext.Current.CancellationToken);

        var result = await host.GetRequiredKeyedService<ISecurityEventTokenValidator>("test")
            .ValidateAsync(compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.MalformedToken, error.Code);
        Assert.Equal(DeliveryErrorCodes.InvalidRequest, DeliveryErrorCodes.FromValidationError(error.Code));
    }

    [Fact]
    public async Task IssuerWithNoKeys_IsRejected_AsKeyNotFound()
    {
        // The recoverable failure: after a key rollover a refetch may heal this, which a wrong
        // signature never becomes - the receiver's retry logic branches on exactly this code.
        JsonWebKey key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.AddSingleton<IIssuerKeyResolver>(new FixedKeyResolver());
        services.AddSecurityEvents(options => options.SigningKeySource = _ => Task.FromResult(key));
        services.AddSecurityEventValidationProfile("test", profile => profile.UseDefaultPipeline());
        await using var host = services.BuildServiceProvider();

        var compact = await SignedCompact(host);

        var result = await host.GetRequiredKeyedService<ISecurityEventTokenValidator>("test")
            .ValidateAsync(compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.KeyNotFound, error.Code);
    }

    [Fact]
    public async Task Signer_WithoutAConfiguredKeySource_FailsNamingTheOption()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IIssuerKeyResolver>(new FixedKeyResolver());
        services.AddSecurityEvents();
        services.AddSecurityEventValidationProfile("test", profile => profile.UseDefaultPipeline());
        await using var host = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(
            () => host.GetRequiredService<ISecurityEventTokenSigner>());

        Assert.Contains(nameof(SecurityEventsOptions.SigningKeySource), exception.Message);
    }

    [Fact]
    public async Task HostRegistrations_Win_OverThePackageDefaults()
    {
        // The DI rule of this repository: a library extension supplies defaults and never
        // overrides what the host already registered.
        var services = new ServiceCollection();
        services.AddLogging();
        var hostVerifier = new HostVerifier();
        services.AddSingleton<ISecurityEventTokenVerifier>(hostVerifier);
        services.AddSecurityEvents();
        services.AddSecurityEventValidationProfile("test", profile => profile.UseDefaultPipeline());
        await using var host = services.BuildServiceProvider();

        Assert.Same(hostVerifier, host.GetRequiredService<ISecurityEventTokenVerifier>());
    }

    [Fact]
    public async Task EventRegistrations_MadeInAddSecurityEvents_ReachTheResolvedRegistry()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecurityEvents(options =>
            options.Events.Register<MembershipChangedPayload>(MembershipChanged));
        services.AddSecurityEventValidationProfile("test", profile => profile.UseDefaultPipeline());
        await using var host = services.BuildServiceProvider();

        Assert.True(
            host.GetRequiredService<EventTypeRegistry>().TryGetPayloadType(MembershipChanged, out var type));
        Assert.Equal(typeof(MembershipChangedPayload), type);
    }

    private sealed class MembershipChangedPayload : IEventPayload;

    private sealed class HostVerifier : ISecurityEventTokenVerifier
    {
        public Task<Abblix.Utils.Result<JsonWebToken, SecurityEventTokenValidationError>> VerifyAsync(
            string compactToken,
            string? keyId = null,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException("Registration identity is the assertion; this never runs.");
    }
}
