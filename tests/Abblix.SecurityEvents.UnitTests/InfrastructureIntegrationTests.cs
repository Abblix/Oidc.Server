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

using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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
            options.SigningKeySource = _ => ValueTask.FromResult(signingKey);
        });

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

        var result = await host.GetRequiredService<ISecurityEventTokenValidator>()
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

        var result = await host.GetRequiredService<ISecurityEventTokenValidator>()
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

        var result = await host.GetRequiredService<ISecurityEventTokenValidator>()
            .ValidateAsync(compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.SignatureInvalid, error.Code);
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
        services.AddSecurityEvents(options => options.SigningKeySource = _ => ValueTask.FromResult(key));
        await using var host = services.BuildServiceProvider();

        var compact = await SignedCompact(host);

        var result = await host.GetRequiredService<ISecurityEventTokenValidator>()
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
