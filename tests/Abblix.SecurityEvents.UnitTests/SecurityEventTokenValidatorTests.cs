// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Abblix.Utils;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Exercises the default pipeline end to end over a fake verifier: every error code of the
/// receiver profile against the input that earns it, and the happy path yielding a validated
/// token with typed payloads. The verifier is the one faked seam - each check under test is real.
/// </summary>
public class SecurityEventTokenValidatorTests
{
    private const string Issuer = "https://tenant.example.com";
    private const string Audience = "https://receiver.example.com/events";
    private const string MembershipChanged = "https://tenant.example.com/events/membership-changed";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    private sealed class MembershipChangedPayload : IEventPayload
    {
        [JsonPropertyName("change")]
        public string? Change { get; init; }
    }

    /// <summary>
    /// A verifier that accepts everything, returning the compact token's own parsed claims - the
    /// signature seam faked so every other check stays real.
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

    /// <summary>
    /// A verifier that rejects everything with the given error, standing in for a signature or
    /// key failure.
    /// </summary>
    private sealed class RejectingVerifier(SecurityEventTokenValidationError error) : ISecurityEventTokenVerifier
    {
        public Task<Result<JsonWebToken, SecurityEventTokenValidationError>> VerifyAsync(
            string compactToken,
            string? keyId = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult(Result<JsonWebToken, SecurityEventTokenValidationError>.Failure(error));
    }

    private static string EncodeCompact(SecurityEventToken token)
    {
        var header = Base64Url.EncodeToString(
            Encoding.UTF8.GetBytes(token.Token.Header.Json.ToJsonString()));
        var payload = Base64Url.EncodeToString(
            Encoding.UTF8.GetBytes(token.Token.Payload.Json.ToJsonString()));

        // The signature segment is opaque to every step but the verifier, and the verifier here
        // is a fake: any value marks the position.
        return $"{header}.{payload}.signature";
    }

    private static string ConformantCompact(Action<SecurityEventTokenBuilder>? mutate = null)
    {
        var builder = new SecurityEventTokenBuilder()
            .WithIssuer(Issuer)
            .WithJwtId("jti-1")
            .WithIssuedAt(Now)
            .WithAudience(Audience)
            .WithEvent(MembershipChanged, new JsonObject { ["change"] = "revoked" });

        mutate?.Invoke(builder);
        return EncodeCompact(builder.Build());
    }

    private static ISecurityEventTokenValidator DefaultValidator(
        ISecurityEventTokenVerifier? verifier = null,
        EventTypeRegistry? registry = null)
    {
        if (registry is null)
        {
            registry = new EventTypeRegistry();
            registry.Register<MembershipChangedPayload>(MembershipChanged);
        }

        // The default profile assembled by hand, in its required order: these tests judge the
        // steps' behaviour, and the composition machinery has its own suite.
        return new CompositeSecurityEventTokenValidator(
        [
            new ParseStep(),
            new TypHeaderStep(),
            new ExpAbsenceStep(),
            new EventsPresenceStep(),
            new JwtIdPresenceStep(),
            new IssuerAllowlistStep(),
            new SignatureStep(verifier ?? new AcceptingVerifier()),
            new AudienceStep(),
            new IssuedAtWindowStep(new FakeTimeProvider(Now)),
            new PayloadDeserializationStep(registry),
        ]);
    }

    private static SecurityEventTokenValidationOptions DefaultOptions() => new()
    {
        ExpectedAudience = Audience,
        ExpectedIssuers = [Issuer],
    };

    private static async Task<SecurityEventTokenValidationError> ValidateExpectingError(
        string compact,
        ISecurityEventTokenVerifier? verifier = null)
    {
        var result = await DefaultValidator(verifier)
            .ValidateAsync(compact, DefaultOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error), "Validation unexpectedly succeeded.");
        return error;
    }

    [Fact]
    public async Task ConformantToken_PassesTheDefaultPipeline_WithTypedPayloads()
    {
        var result = await DefaultValidator()
            .ValidateAsync(ConformantCompact(), DefaultOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated), "Validation unexpectedly failed.");
        Assert.Equal(Issuer, validated.Token.Issuer);
        Assert.Equal("jti-1", validated.Token.JwtId);

        Assert.NotNull(validated.EventPayloads);
        var payload = Assert.IsType<MembershipChangedPayload>(validated.EventPayloads[MembershipChanged]);
        Assert.Equal("revoked", payload.Change);
    }

    [Theory]
    [InlineData("only-one-segment")]
    [InlineData("two.segments")]
    [InlineData("four.whole.segments.here")]
    public async Task WrongSegmentCount_IsMalformed(string compact)
    {
        var error = await ValidateExpectingError(compact);
        Assert.Equal(SecurityEventTokenErrorCode.MalformedToken, error.Code);
    }

    [Fact]
    public async Task JweToken_IsReportedAsUnsupported_NotAsGenericGarbage()
    {
        var error = await ValidateExpectingError("a.b.c.d.e");
        Assert.Equal(SecurityEventTokenErrorCode.DecryptionFailed, error.Code);
    }

    [Fact]
    public async Task UndecodableSegment_IsMalformed()
    {
        var error = await ValidateExpectingError("!!!.???.###");
        Assert.Equal(SecurityEventTokenErrorCode.MalformedToken, error.Code);
    }

    [Fact]
    public async Task WrongTyp_IsTokenConfusion()
    {
        // A JWT with perfect SET claims but another type: the substitution attack of
        // RFC 8417 Section 4, caught by the explicit-typing wall.
        var compact = ConformantCompact();
        var segments = compact.Split('.');
        var header = Base64Url.EncodeToString("""{"typ":"at+jwt","alg":"none"}"""u8);

        var error = await ValidateExpectingError($"{header}.{segments[1]}.{segments[2]}");
        Assert.Equal(SecurityEventTokenErrorCode.TokenConfusion, error.Code);
    }

    [Fact]
    public async Task MissingTyp_IsTokenConfusion()
    {
        var compact = ConformantCompact();
        var segments = compact.Split('.');
        var header = Base64Url.EncodeToString("""{"alg":"none"}"""u8);

        var error = await ValidateExpectingError($"{header}.{segments[1]}.{segments[2]}");
        Assert.Equal(SecurityEventTokenErrorCode.TokenConfusion, error.Code);
    }

    [Fact]
    public async Task ApplicationPrefixedTyp_IsAccepted()
    {
        // RFC 7515 Section 4.1.9 makes "application/secevent+jwt" and "secevent+jwt" the same
        // name; a receiver rejecting the long spelling would refuse conformant issuers.
        var compact = ConformantCompact();
        var segments = compact.Split('.');
        var header = Base64Url.EncodeToString("""{"typ":"application/secevent+jwt","alg":"none"}"""u8);

        var result = await DefaultValidator().ValidateAsync(
            $"{header}.{segments[1]}.{segments[2]}",
            DefaultOptions(),
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out _));
    }

    [Fact]
    public async Task PresentExp_IsTokenConfusion()
    {
        // The builder refuses to write "exp", so the token is forged the way an attacker would:
        // by editing the claims directly.
        var compact = ConformantCompact();
        var segments = compact.Split('.');
        var claims = (JsonObject)JsonNode.Parse(
            Encoding.UTF8.GetString(Base64Url.DecodeFromChars(segments[1])))!;
        claims[JwtClaimTypes.ExpiresAt] = Now.ToUnixTimeSeconds() + 300;
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(claims.ToJsonString()));

        var error = await ValidateExpectingError($"{segments[0]}.{payload}.{segments[2]}");
        Assert.Equal(SecurityEventTokenErrorCode.TokenConfusion, error.Code);
    }

    [Theory]
    // Absent, empty, and non-object "events" are three spellings of the same defect.
    [InlineData("""{"iss":"https://tenant.example.com","jti":"1","iat":1754040000}""")]
    [InlineData("""{"iss":"https://tenant.example.com","jti":"1","iat":1754040000,"events":{}}""")]
    [InlineData("""{"iss":"https://tenant.example.com","jti":"1","iat":1754040000,"events":"nope"}""")]
    public async Task MissingOrEmptyOrNonObjectEvents_IsMissingEvents(string claimsJson)
    {
        var header = Base64Url.EncodeToString("""{"typ":"secevent+jwt","alg":"none"}"""u8);
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(claimsJson));

        var error = await ValidateExpectingError($"{header}.{payload}.sig");
        Assert.Equal(SecurityEventTokenErrorCode.MissingEvents, error.Code);
    }

    [Theory]
    // Absent, empty, and non-string "jti" are three spellings of the same defect.
    [InlineData("""{"iss":"https://tenant.example.com","iat":1754040000,"aud":"https://receiver.example.com/events","events":{"https://tenant.example.com/events/membership-changed":{}}}""")]
    [InlineData("""{"iss":"https://tenant.example.com","jti":"","iat":1754040000,"aud":"https://receiver.example.com/events","events":{"https://tenant.example.com/events/membership-changed":{}}}""")]
    [InlineData("""{"iss":"https://tenant.example.com","jti":42,"iat":1754040000,"aud":"https://receiver.example.com/events","events":{"https://tenant.example.com/events/membership-changed":{}}}""")]
    public async Task MissingOrEmptyOrNonStringJwtId_IsMalformed(string claimsJson)
    {
        // RFC 8417 Section 2.2 on "jti": "This claim is REQUIRED." A SET without a usable
        // identifier cannot be tracked by any receiver-side replay accounting, so the profile
        // rejects it before spending a signature verification on it.
        var header = Base64Url.EncodeToString("""{"typ":"secevent+jwt","alg":"none"}"""u8);
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(claimsJson));

        var error = await ValidateExpectingError($"{header}.{payload}.sig");
        Assert.Equal(SecurityEventTokenErrorCode.MalformedToken, error.Code);
    }

    [Fact]
    public async Task MissingIssuer_IsUnknownIssuer()
    {
        // The "iss" claim is REQUIRED (RFC 8417 Section 2.2); a token without it names no feed to
        // trust and dies on the allowlist step with the reason spelled out.
        var header = Base64Url.EncodeToString("""{"typ":"secevent+jwt","alg":"none"}"""u8);
        var payload = Base64Url.EncodeToString(
            """{"jti":"1","iat":1754040000,"events":{"urn:example:event":{}}}"""u8);

        var error = await ValidateExpectingError($"{header}.{payload}.sig");
        Assert.Equal(SecurityEventTokenErrorCode.UnknownIssuer, error.Code);
    }

    [Fact]
    public async Task NonObjectEventPayload_IsMalformed()
    {
        // The events object itself is present and non-empty, so the presence step passes; the
        // payload deserialization step is what refuses a statement whose value is not an object
        // (RFC 8417 Section 2.2).
        var header = Base64Url.EncodeToString("""{"typ":"secevent+jwt","alg":"none"}"""u8);
        var payload = Base64Url.EncodeToString(
            """{"iss":"https://tenant.example.com","jti":"1","iat":1754040000,"aud":"https://receiver.example.com/events","events":{"urn:example:event":"not-an-object"}}"""u8);

        var error = await ValidateExpectingError($"{header}.{payload}.sig");
        Assert.Equal(SecurityEventTokenErrorCode.MalformedToken, error.Code);
    }

    [Fact]
    public void ValidationError_PrintsItsDescription()
    {
        // The half of the error a human reads is what logging interpolation gets.
        var error = new SecurityEventTokenValidationError(
            SecurityEventTokenErrorCode.Custom, "the sentence a log reader needs");

        Assert.Equal("the sentence a log reader needs", error.ToString());
    }

    [Fact]
    public async Task UnlistedIssuer_IsUnknownIssuer()
    {
        var compact = ConformantCompact();

        var result = await DefaultValidator().ValidateAsync(
            compact,
            DefaultOptions() with { ExpectedIssuers = ["https://other.example.com"] },
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.UnknownIssuer, error.Code);
    }

    [Fact]
    public async Task NoExpectedIssuers_AcceptsNobody()
    {
        // The unconfigured receiver's safe reading: an empty allowlist is "no", not "anyone".
        var result = await DefaultValidator().ValidateAsync(
            ConformantCompact(),
            DefaultOptions() with { ExpectedIssuers = [] },
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.UnknownIssuer, error.Code);
    }

    [Fact]
    public async Task VerifierRejection_IsRelayedVerbatim()
    {
        // Only the implementation can tell a bad signature from a missing key, so the pipeline
        // must not reinterpret its verdict.
        var verdict = new SecurityEventTokenValidationError(
            SecurityEventTokenErrorCode.KeyNotFound,
            "No key of the issuer matches 'kid-42'.");

        var error = await ValidateExpectingError(ConformantCompact(), new RejectingVerifier(verdict));
        Assert.Same(verdict, error);
    }

    [Fact]
    public async Task WrongAudience_IsAudienceMismatch()
    {
        var compact = ConformantCompact();

        var result = await DefaultValidator().ValidateAsync(
            compact,
            DefaultOptions() with { ExpectedAudience = "https://somebody-else.example.com" },
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.AudienceMismatch, error.Code);
    }

    [Theory]
    // Stale beyond the window, from the future beyond the window: both sides of the clock.
    [InlineData(-600)]
    [InlineData(600)]
    public async Task IssuedAtOutsideTheWindow_IsIatOutOfRange(int offsetSeconds)
    {
        var compact = ConformantCompact(builder => builder.WithIssuedAt(Now.AddSeconds(offsetSeconds)));

        var error = await ValidateExpectingError(compact);
        Assert.Equal(SecurityEventTokenErrorCode.IatOutOfRange, error.Code);
    }

    /// <summary>
    /// The SET is verified without lifetime handling, so the issued-at window step is the first
    /// reader of the claim - and a value no date can hold, written by the transmitter, was an
    /// unhandled exception out of the intake. It is a refusal naming the claim.
    /// </summary>
    [Fact]
    public async Task IssuedAtOutsideTheRepresentableRange_IsMalformedNamingTheClaim()
    {
        var header = Base64Url.EncodeToString("""{"typ":"secevent+jwt","alg":"none"}"""u8);
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(
            """{"iss":"https://tenant.example.com","jti":"1","iat":99999999999999,"aud":"https://receiver.example.com/events","events":{"https://tenant.example.com/events/membership-changed":{}}}"""));

        var error = await ValidateExpectingError($"{header}.{payload}.sig");

        Assert.Equal(SecurityEventTokenErrorCode.MalformedToken, error.Code);
        Assert.Contains("iat", error.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MalformedPayloadOfARegisteredType_IsMalformedToken()
    {
        var compact = ConformantCompact();
        var segments = compact.Split('.');
        var claims = (JsonObject)JsonNode.Parse(
            Encoding.UTF8.GetString(Base64Url.DecodeFromChars(segments[1])))!;
        claims[JwtClaimTypes.Events] = new JsonObject
        {
            [MembershipChanged] = new JsonObject { ["change"] = new JsonObject() },
        };
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(claims.ToJsonString()));

        var error = await ValidateExpectingError($"{segments[0]}.{payload}.{segments[2]}");
        Assert.Equal(SecurityEventTokenErrorCode.MalformedToken, error.Code);
    }

    [Fact]
    public async Task UnregisteredEventType_PassesAsRawPassthrough()
    {
        var compact = ConformantCompact();

        var result = await DefaultValidator(registry: new EventTypeRegistry())
            .ValidateAsync(compact, DefaultOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.NotNull(validated.EventPayloads);
        Assert.IsType<UnknownEventPayload>(validated.EventPayloads[MembershipChanged]);
    }

    [Fact]
    public async Task MisorderedPipeline_FailsLoudlyOnFirstRun()
    {
        // AudienceStep reads trusted claims, so a pipeline running it before the signature step
        // is unsafe by construction - and says so on run one, not month three.
        var validator = new CompositeSecurityEventTokenValidator([new ParseStep(), new AudienceStep()]);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => validator.ValidateAsync(
                ConformantCompact(),
                DefaultOptions(),
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task UnconfiguredExpectedAudience_ThrowsAsAConfigurationBug_NotATokenError()
    {
        // An empty expectation must never become an "invalid token" verdict: with the check
        // inverted a receiver would accept every audience for months while the logs blame the
        // tokens, so AudienceStep treats the hole in the options as the receiver's own defect.
        var options = new SecurityEventTokenValidationOptions { ExpectedIssuers = [Issuer] };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => DefaultValidator().ValidateAsync(
                ConformantCompact(),
                options,
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task PipelineWithoutATokenProducingStep_FailsLoudly_NotWithANull()
    {
        var validator = new CompositeSecurityEventTokenValidator([new ParseStep()]);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => validator.ValidateAsync(
                ConformantCompact(),
                DefaultOptions(),
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public void EmptyPipeline_IsRejectedAtConstruction()
    {
        Assert.Throws<ArgumentException>(() => new CompositeSecurityEventTokenValidator([]));
    }
}
