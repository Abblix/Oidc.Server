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
/// Driven through <see cref="ServiceCollectionExtensions.AddBackChannelLogoutReceiver"/> on
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
}
