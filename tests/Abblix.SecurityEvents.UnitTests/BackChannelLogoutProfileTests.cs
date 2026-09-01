// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.BackChannelLogout;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// The Back-Channel Logout profile as a host gets it, resolved from the registration rather than
/// composed here: a profile that disagrees with the security-event default on two
/// security-critical points - its own rule for "typ", a REQUIRED "exp" - and adds three checks of
/// its own, without one line of the security-event package changing.
/// </summary>
/// <remarks>
/// Driven through <see cref="Infrastructure.ServiceCollectionExtensions.AddBackChannelLogoutReceiver"/> on
/// purpose. A suite that composed the same profile itself would prove the composite can be
/// reshaped and say nothing about whether the shipped registration reshapes it that way, which is
/// the only question a host's token depends on.
/// </remarks>
public class BackChannelLogoutProfileTests
{
    private const string Issuer = "https://op.example.com";
    private const string ClientId = "client_123";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    /// <summary>
    /// A verifier that accepts everything, returning the compact token's own parsed claims: this
    /// suite proves composition, and the cryptography is proven by the integration tests.
    /// </summary>
    private sealed class AcceptingVerifier : ISecurityEventTokenVerifier
    {
        public Task<Result<JsonWebToken, SecurityEventTokenValidationError>> VerifyAsync(
            string compactToken,
            string? keyId = null,
            CancellationToken cancellationToken = default)
        {
            var segments = compactToken.Split('.');
            var token = new JsonWebToken
            {
                Header = new JsonWebTokenHeader(DecodeSegment(segments[0])),
                Payload = new JsonWebTokenPayload(DecodeSegment(segments[1])),
            };

            return Task.FromResult(Result<JsonWebToken, SecurityEventTokenValidationError>.Success(token));
        }

        private static JsonObject DecodeSegment(string segment)
            => (JsonObject)JsonNode.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(segment)))!;
    }

    private static ISecurityEventTokenValidator LogoutProfileValidator()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.AddSingleton<ISecurityEventTokenVerifier>(new AcceptingVerifier());
        services.AddSecurityEvents();

        services.AddBackChannelLogoutReceiver(new BackChannelLogoutValidationOptions
        {
            ExpectedAudience = ClientId,
            ExpectedIssuers = [Issuer],
        });

        return services.BuildServiceProvider()
            .GetRequiredKeyedService<ISecurityEventTokenValidator>(
                ValidationProfileKeys.LogoutToken);
    }

    private static SecurityEventTokenValidationOptions ReceiverOptions() => new()
    {
        ExpectedAudience = ClientId,
        ExpectedIssuers = [Issuer],
    };

    private static string LogoutCompact(Action<JsonWebToken>? mutate = null)
    {
        var built = new SecurityEventTokenBuilder(new FakeTimeProvider(Now))
            .WithIssuer(Issuer)
            .WithAudience(ClientId)
            .WithJwtId("jti-1")
            .WithSubject("user_456")
            .WithClaim(IanaClaimTypes.Sid, "session_789")
            .WithEvent(LogoutTokenClaims.BackChannelLogoutEvent)
            .Build();

        // The logout shape the provider emits: its own type and a required lifetime, written
        // through the open model exactly as the producing side writes them.
        built.Token.Header.Type = JsonWebTokenTypes.LogoutToken;
        built.Token.Payload.ExpiresAt = Now + TimeSpan.FromMinutes(5);

        mutate?.Invoke(built.Token);

        var header = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(built.Token.Header.Json.ToJsonString()));
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(built.Token.Payload.Json.ToJsonString()));
        return $"{header}.{payload}.signature";
    }

    [Fact]
    public async Task ALogoutToken_PassesTheLogoutProfile()
    {
        var result = await LogoutProfileValidator().ValidateAsync(
            LogoutCompact(), ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated), "Validation unexpectedly failed.");
        Assert.Equal("user_456", validated.Token.Subject);
    }

    /// <summary>
    /// OpenID Connect Back-Channel Logout 1.0 Section 4.1: "requiring explicitly typed Logout
    /// Tokens will break most existing deployments, as existing OPs and RPs are already commonly
    /// using untyped Logout Tokens". So the untyped token is the conformant one this receiver
    /// would refuse if its type rule were written as a requirement rather than a refusal.
    /// </summary>
    [Fact]
    public async Task AnUntypedLogoutToken_PassesTheLogoutProfile()
    {
        var compact = LogoutCompact(token => token.Header.Json.Remove(JwtClaimTypes.Type));

        var result = await LogoutProfileValidator().ValidateAsync(
            compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out _), "An untyped Logout Token was refused.");
    }

    [Fact]
    public async Task AGenericSecurityEventToken_IsRefused_ByTheLogoutProfile()
    {
        // Mutual exclusion cuts both ways: the profile that relaxed the default "typ" check did
        // not stop typing - it refuses a type belonging to another kind.
        var compact = LogoutCompact(token => token.Header.Type = SecurityEventToken.TokenType);

        var result = await LogoutProfileValidator().ValidateAsync(
            compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.TokenConfusion, error.Code);
    }

    [Fact]
    public async Task AMissingExpiration_IsRefused()
    {
        var compact = LogoutCompact(token => token.Payload.Json.Remove(JwtClaimTypes.ExpiresAt));

        var result = await LogoutProfileValidator().ValidateAsync(
            compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.Custom, error.Code);
    }

    /// <summary>
    /// Section 2.6 step 4 validates "exp" as an ID Token's is validated, so a token whose expiry
    /// has passed is refused - the presence check alone would leave a captured token usable for as
    /// long as anyone kept it.
    /// </summary>
    [Fact]
    public async Task AnExpiredLogoutToken_IsRefused()
    {
        var compact = LogoutCompact(token => token.Payload.ExpiresAt = Now - TimeSpan.FromHours(1));

        var result = await LogoutProfileValidator().ValidateAsync(
            compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.Custom, error.Code);
    }

    [Fact]
    public async Task ANonce_IsRefused()
    {
        var compact = LogoutCompact(token => token.Payload.Nonce = "n-0S6_WzA2Mj");

        var result = await LogoutProfileValidator().ValidateAsync(
            compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.TokenConfusion, error.Code);
    }

    [Fact]
    public async Task NeitherSubNorSid_IsRefused()
    {
        var compact = LogoutCompact(token =>
        {
            token.Payload.Json.Remove(JwtClaimTypes.Subject);
            token.Payload.Json.Remove(JwtClaimTypes.SessionId);
        });

        var result = await LogoutProfileValidator().ValidateAsync(
            compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.Custom, error.Code);
    }

    [Fact]
    public async Task ADifferentEventType_IsRefused()
    {
        var compact = LogoutCompact(token =>
        {
            token.Payload.Json[JwtClaimTypes.Events] = new JsonObject
            {
                ["https://example.com/events/something-else"] = new JsonObject(),
            };
        });

        var result = await LogoutProfileValidator().ValidateAsync(
            compact, ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.Custom, error.Code);
    }
    /// <summary>
    /// The signature algorithm policy reaches a Logout Token, because the verifier is shared - so the
    /// default admits RS256 and refuses ES256 until a host widens it.
    /// </summary>
    /// <remarks>
    /// Every other row in this class substitutes an accepting verifier, which is right for what they
    /// measure and is exactly why none of them can see this: the policy lives in the real one. Driven
    /// through the whole profile with a REAL key and a real signature, because the claim is about what a
    /// deployment meets, not about what a step does when asked directly.
    /// <para>
    /// RS256 is the case that must keep working without anybody configuring anything, and it is not a
    /// coincidence: Back-Channel Logout 1.0 Section 2.6 names RS256 as the default for a Logout Token,
    /// this server's own logout tokens carry it unless a client registered otherwise, and the security
    /// event default is the same value. ES256 is the case that must be REFUSED and must say why - a host
    /// whose provider signs that way widens the set, and the refusal is the only place it learns to.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, true)]
    [InlineData(SigningAlgorithms.ES256, false)]
    public async Task TheAlgorithmPolicy_ReachesALogoutToken(string algorithm, bool acceptedByDefault)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        JsonWebKey key = algorithm == SigningAlgorithms.ES256
            ? JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256)
            : JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, algorithm);

        var compact = await SignedLogoutTokenAsync(key, algorithm, cancellationToken);

        var result = await RealVerifierProfile(key).ValidateAsync(
            compact, ReceiverOptions(), cancellationToken);

        Assert.Equal(acceptedByDefault, result.TryGetSuccess(out _));

        if (acceptedByDefault)
            return;

        // The refusal has to be actionable: a policy decision answered the way a tampered token is
        // answered sends an operator looking for an attacker while the fix is one line of configuration.
        Assert.True(result.TryGetFailure(out var error));
        Assert.NotEqual(SecurityEventTokenErrorCode.SignatureInvalid, error.Code);
        Assert.Contains(algorithm, error.Description, StringComparison.Ordinal);
        Assert.Contains(
            nameof(SecurityEventsOptions.AllowedSigningAlgorithms),
            error.Description,
            StringComparison.Ordinal);

        // And widening admits it, which is what the documentation tells such a host to do.
        var widened = await RealVerifierProfile(key, [algorithm]).ValidateAsync(
            compact, ReceiverOptions(), cancellationToken);

        Assert.True(widened.TryGetSuccess(out _), $"{algorithm} was refused after widening.");
    }

    /// <summary>
    /// A Logout Token signed for real, the way a provider emits one.
    /// </summary>
    private static async Task<string> SignedLogoutTokenAsync(
        JsonWebKey key, string algorithm, CancellationToken cancellationToken)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.AddSecurityEvents(options =>
        {
            options.SigningKeySource = _ => Task.FromResult(key);
            options.AllowedSigningAlgorithms = [algorithm];
        });

        await using var transmitter = services.BuildServiceProvider();

        var built = new SecurityEventTokenBuilder(new FakeTimeProvider(Now))
            .WithIssuer(Issuer)
            .WithAudience(ClientId)
            .WithJwtId("jti-1")
            .WithSubject("user_456")
            .WithClaim(IanaClaimTypes.Sid, "session_789")
            .WithEvent(LogoutTokenClaims.BackChannelLogoutEvent)
            .Build();

        built.Token.Header.Type = JsonWebTokenTypes.LogoutToken;
        built.Token.Payload.ExpiresAt = Now + TimeSpan.FromMinutes(5);

        return await transmitter.GetRequiredService<ISecurityEventTokenSigner>()
            .SignAsync(built, cancellationToken);
    }

    /// <summary>
    /// The logout profile with the REAL verifier, and the algorithm set a host would have.
    /// </summary>
    private static ISecurityEventTokenValidator RealVerifierProfile(
        JsonWebKey key, string[]? allowedAlgorithms = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.AddSingleton<IIssuerKeyResolver>(new SingleKeyResolver(key));
        services.AddSecurityEvents(options => options.AllowedSigningAlgorithms = allowedAlgorithms);

        services.AddBackChannelLogoutReceiver(new BackChannelLogoutValidationOptions
        {
            ExpectedAudience = ClientId,
            ExpectedIssuers = [Issuer],
        });

        return services.BuildServiceProvider()
            .GetRequiredKeyedService<ISecurityEventTokenValidator>(ValidationProfileKeys.LogoutToken);
    }

    private sealed class SingleKeyResolver(JsonWebKey key) : IIssuerKeyResolver
    {
        public async IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
            string issuer,
            string? keyId = null,
            [System.Runtime.CompilerServices.EnumeratorCancellation]
            CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return key;
        }
    }
}
