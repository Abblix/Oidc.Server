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
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.DependencyInjection;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// The Back-Channel Logout receiver profile assembled AS A CONSUMER WOULD assemble it - the
/// plan's flagship test of the composite: a profile that disagrees with the SET default on two
/// security-critical points (its own "typ", a REQUIRED "exp") and adds three checks of its own,
/// all without one line of the package changing. The two disagreements go through the reasoned
/// allowance door, which is exactly the visibility that door exists to force.
/// </summary>
public class BackChannelLogoutProfileTests
{
    private const string Issuer = "https://op.example.com";
    private const string ClientId = "client_123";
    [SuppressMessage("Minor Vulnerability", "S5332:Using clear-text protocols is security-sensitive",
        Justification = "The value is an event identifier compared verbatim (OpenID Back-Channel Logout 1.0 Section 2.4), not an address anything connects to; the https spelling would be a different identifier no receiver recognises.")]
    private const string LogoutEventType = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    /// <summary>
    /// Requires the "typ" of Back-Channel Logout Section 2.4, "logout+jwt". Critical itself: the
    /// step it replaces guarded token confusion, and this profile still does - just for its own
    /// type, and in both directions: a generic SET is exactly as refused here as a logout token
    /// is by the default profile.
    /// </summary>
    private sealed class LogoutTokenTypeStep : ISecurityCriticalValidator
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context,
            CancellationToken cancellationToken)
        {
            context.Require(SecurityEventTokenValidationStates.Parsed);

            SecurityEventTokenValidationError? error;
            if (JwtTypeName.Matches(context.UnverifiedHeader!.Type, JsonWebTokenTypes.LogoutToken))
            {
                context.Establish(SecurityEventTokenValidationStates.TypVerified);
                error = null;
            }
            else
            {
                error = new SecurityEventTokenValidationError(
                    SecurityEventTokenErrorCode.TokenConfusion,
                    $"A logout token carries '{JsonWebTokenTypes.LogoutToken}', not "
                    + $"'{context.UnverifiedHeader.Type}'.");
            }

            return ValueTask.FromResult(error);
        }
    }

    /// <summary>
    /// Requires "exp" to be PRESENT - Back-Channel Logout inverts the SET default, because for a
    /// logout order the expiry is what bounds how long a lost token still logs somebody out.
    /// Critical itself: it replaces a critical step and still polices the same claim, with the
    /// opposite sign.
    /// </summary>
    private sealed class ExpRequiredStep : ISecurityCriticalValidator
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context,
            CancellationToken cancellationToken)
        {
            context.Require(SecurityEventTokenValidationStates.Parsed);

            var error = context.UnverifiedPayload!.Json.ContainsKey(JwtClaimTypes.ExpiresAt)
                ? null
                : new SecurityEventTokenValidationError(
                    SecurityEventTokenErrorCode.Custom,
                    "Back-Channel Logout requires the logout token to carry an expiration time.");

            return ValueTask.FromResult(error);
        }
    }

    /// <summary>
    /// "A Logout Token MUST contain either a sub or a sid Claim, and MAY contain both."
    /// </summary>
    private sealed class RequireSidOrSubStep : ISecurityEventTokenValidator
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context,
            CancellationToken cancellationToken)
        {
            context.Require(SecurityEventTokenValidationStates.SignatureVerified);

            var payload = context.Token!.Token.Payload;
            var error = payload.Subject is not null || payload.SessionId is not null
                ? null
                : new SecurityEventTokenValidationError(
                    SecurityEventTokenErrorCode.Custom,
                    "A logout token names its target through 'sub', 'sid', or both; this one has neither.");

            return ValueTask.FromResult(error);
        }
    }

    /// <summary>
    /// The logout event statement must be present: it is what makes the token a logout order and
    /// not some other event that happens to share the envelope.
    /// </summary>
    private sealed class RequireLogoutEventTypeStep : ISecurityEventTokenValidator
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context,
            CancellationToken cancellationToken)
        {
            context.Require(
                SecurityEventTokenValidationStates.SignatureVerified
                | SecurityEventTokenValidationStates.EventsPresent);

            var error = context.Token!.Events!.Contains(LogoutEventType)
                ? null
                : new SecurityEventTokenValidationError(
                    SecurityEventTokenErrorCode.Custom,
                    "The events claim carries no back-channel logout statement.");

            return ValueTask.FromResult(error);
        }
    }

    /// <summary>
    /// "Logout Tokens MUST NOT contain a nonce Claim" - the wall that keeps a logout token from
    /// being replayed where an ID token is expected.
    /// </summary>
    private sealed class ForbidNonceStep : ISecurityEventTokenValidator
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context,
            CancellationToken cancellationToken)
        {
            context.Require(SecurityEventTokenValidationStates.Parsed);

            var error = context.UnverifiedPayload!.Json.ContainsKey(JwtClaimTypes.Nonce)
                ? new SecurityEventTokenValidationError(
                    SecurityEventTokenErrorCode.TokenConfusion,
                    "A logout token must not carry 'nonce'; a token carrying it could double as an ID token.")
                : null;

            return ValueTask.FromResult(error);
        }
    }

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
        // The profile is composed the way a real consumer composes it: a NAMED profile of the
        // package's defaults, edited through its own cursor, with the two critical departures
        // acknowledged on the profile itself - where the boot log will surface them.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.AddSingleton<ISecurityEventTokenVerifier>(new AcceptingVerifier());
        services.AddSecurityEvents();

        services.AddSecurityEventValidationProfile(JsonWebTokenTypes.LogoutToken, profile =>
        {
            profile.Steps
                .Replace<TypHeaderStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, LogoutTokenTypeStep>())
                .Replace<ExpAbsenceStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, ExpRequiredStep>())
                .AddAfter<ParseStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, ForbidNonceStep>())
                .AddAfter<SignatureStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, RequireSidOrSubStep>())
                .AddAfter<RequireSidOrSubStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, RequireLogoutEventTypeStep>());

            profile
                .AllowInsecureValidation(
                    "Back-Channel Logout types its token 'logout+jwt'; the replacement pins that value and "
                    + "is itself security-critical")
                .AllowInsecureValidation(
                    "Back-Channel Logout REQUIRES 'exp', inverting the SET default; the replacement polices "
                    + "the same claim with the opposite sign");
        });

        return services.BuildServiceProvider()
            .GetRequiredKeyedService<ISecurityEventTokenValidator>(JsonWebTokenTypes.LogoutToken);
    }

    private static string LogoutCompact(Action<JsonWebToken>? mutate = null)
    {
        var built = new SecurityEventTokenBuilder(new FakeTimeProvider(Now))
            .WithIssuer(Issuer)
            .WithAudience(ClientId)
            .WithJwtId("jti-1")
            .WithSubject("user_456")
            .WithClaim(IanaClaimTypes.Sid, "session_789")
            .WithEvent(LogoutEventType)
            .Build();

        // The logout shape the OP emits: its own type and a required lifetime, written through
        // the open model exactly as the producing side writes them.
        built.Token.Header.Type = JsonWebTokenTypes.LogoutToken;
        built.Token.Payload.ExpiresAt = Now + TimeSpan.FromMinutes(5);

        mutate?.Invoke(built.Token);

        var header = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(built.Token.Header.Json.ToJsonString()));
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(built.Token.Payload.Json.ToJsonString()));
        return $"{header}.{payload}.signature";
    }

    private static SecurityEventTokenValidationOptions ReceiverOptions() => new()
    {
        ExpectedAudience = ClientId,
        ExpectedIssuers = [Issuer],
    };

    [Fact]
    public async Task ALogoutToken_PassesTheLogoutProfile()
    {
        var result = await LogoutProfileValidator().ValidateAsync(
            LogoutCompact(), ReceiverOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated), "Validation unexpectedly failed.");
        Assert.Equal("user_456", validated.Token.Subject);
    }

    [Fact]
    public async Task AGenericSecurityEventToken_IsRefused_ByTheLogoutProfile()
    {
        // Mutual exclusion cuts both ways: the profile that relaxed the default "typ" check did
        // not relax typing - it pinned its own value.
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
