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

using System.Net;
using Abblix.SecurityEvents;
using Abblix.Jwt.ReplayPrevention;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Validation;
using Abblix.SharedSignals.Receiver;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the push intake core (RFC 8935 Sections 2.1-2.4): what earns the empty 202, what earns
/// the 400 with a registry-coded body, and the order - validation decides before the replay
/// cache is asked, the sink consumes only what both let through, and a redelivery is
/// acknowledged without re-processing.
/// </summary>
public class PushDeliveryHandlerTests
{
    private const string SetMediaType = "application/secevent+jwt";

    private static SecurityEventToken BuildToken(string jwtId = "set-1")
        => new SecurityEventTokenBuilder()
            .WithIssuer("https://tr.example.com")
            .WithJwtId(jwtId)
            .WithEvent("https://example.com/events/test")
            .Build();

    private sealed class StubValidator(SecurityEventTokenValidationError? error, SecurityEventToken? token)
        : ISecurityEventTokenValidator
    {
        public int Calls { get; private set; }

        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context,
            CancellationToken cancellationToken)
        {
            Calls++;
            context.Token = token;
            return ValueTask.FromResult(error);
        }
    }

    private sealed class RecordingSink(DeliveryError? refusal = null) : ISecurityEventSink
    {
        public List<ValidatedSecurityEventToken> Consumed { get; } = [];

        public Task<DeliveryError?> ConsumeAsync(
            ValidatedSecurityEventToken token,
            CancellationToken cancellationToken = default)
        {
            Consumed.Add(token);
            return Task.FromResult(refusal);
        }
    }

    private sealed class FakeReplayCache : IReplayCache
    {
        private readonly HashSet<string> _seen = [];

        public Task<bool> TryReserveAsync(
            string identifier,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
            => Task.FromResult(_seen.Add(identifier));
    }

    [Fact]
    public async Task WrongContentType_IsRejected_BeforeAnyValidation()
    {
        var validator = new StubValidator(error: null, token: BuildToken());
        var sink = new RecordingSink();
        var handler = new PushDeliveryHandler(validator, new SharedSignalsValidationOptions(), sink);

        var result = await handler.HandleAsync(
            "application/json", "a.b.c", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Equal(DeliveryErrorCodes.InvalidRequest, result.Error!.Error);
        Assert.Equal(0, validator.Calls);
        Assert.Empty(sink.Consumed);
    }

    [Fact]
    public async Task ContentTypeParameters_DoNotFailAConformantTransmitter()
    {
        var handler = new PushDeliveryHandler(
            new StubValidator(error: null, token: BuildToken()),
            new SharedSignalsValidationOptions(),
            new RecordingSink());

        var result = await handler.HandleAsync(
            $"{SetMediaType}; charset=utf-8", "a.b.c", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Accepted, result.StatusCode);
        Assert.Null(result.Error);
    }

    [Fact]
    public async Task EmptyBody_IsRejected()
    {
        var handler = new PushDeliveryHandler(
            new StubValidator(error: null, token: BuildToken()),
            new SharedSignalsValidationOptions(),
            new RecordingSink());

        var result = await handler.HandleAsync(SetMediaType, "", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Equal(DeliveryErrorCodes.InvalidRequest, result.Error!.Error);
    }

    [Fact]
    public async Task ValidationError_TravelsInRegistryVocabulary()
    {
        // The transmitter reads the coarse registry code; the pipeline's own sentence rides
        // beside it, so the operator on the other side loses nothing.
        var validator = new StubValidator(
            new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.AudienceMismatch, "not for this receiver"),
            token: null);
        var sink = new RecordingSink();
        var handler = new PushDeliveryHandler(validator, new SharedSignalsValidationOptions(), sink);

        var result = await handler.HandleAsync(
            SetMediaType, "a.b.c", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Equal(DeliveryErrorCodes.InvalidAudience, result.Error!.Error);
        Assert.Equal("not for this receiver", result.Error.Description);
        Assert.Empty(sink.Consumed);
    }

    [Fact]
    public async Task ValidToken_ReachesTheSink_AndEarnsTheEmptyAccepted()
    {
        var token = BuildToken();
        var sink = new RecordingSink();
        var handler = new PushDeliveryHandler(
            new StubValidator(error: null, token: token), new SharedSignalsValidationOptions(), sink);

        var result = await handler.HandleAsync(
            SetMediaType, "a.b.c", TestContext.Current.CancellationToken);

        Assert.Equal(PushDeliveryResult.Accepted, result);
        Assert.Same(token, Assert.Single(sink.Consumed).Token);
    }

    [Fact]
    public async Task SinkRefusal_TravelsInThe400()
    {
        // The framework's own case: a verification event whose "state" is not what this
        // receiver sent (SSF 1.0 Section 8.1.4.1) - a verdict only the consumer can reach.
        var refusal = new DeliveryError(DeliveryErrorCodes.InvalidState, "state mismatch");
        var handler = new PushDeliveryHandler(
            new StubValidator(error: null, token: BuildToken()),
            new SharedSignalsValidationOptions(),
            new RecordingSink(refusal));

        var result = await handler.HandleAsync(
            SetMediaType, "a.b.c", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Same(refusal, result.Error);
    }

    [Fact]
    public async Task UntrackableEnvelope_WithReplayCache_FailsClosed()
    {
        // The default profile requires "iss", "jti" and "iat" (RFC 8417 Section 2.2), so this
        // token can only come from a weakened profile - and a token replay accounting cannot
        // track must not slip past it. The safe direction is rejection, not consumption.
        var jtiless = new SecurityEventToken(new Abblix.Jwt.JsonWebToken
        {
            Payload = { Issuer = "https://tr.example.com" },
        });
        var sink = new RecordingSink();
        var handler = new PushDeliveryHandler(
            new StubValidator(error: null, token: jtiless),
            new SharedSignalsValidationOptions(),
            sink,
            new FakeReplayCache());

        var result = await handler.HandleAsync(
            SetMediaType, "a.b.c", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Equal(DeliveryErrorCodes.InvalidRequest, result.Error!.Error);
        Assert.Empty(sink.Consumed);
    }

    [Fact]
    public async Task Redelivery_IsAcknowledged_WithoutReprocessing()
    {
        // RFC 8935 Section 2 lets a transmitter redeliver regardless of earlier responses: the
        // repeat is the protocol working, so it earns the same 202 - but the sink runs once.
        var sink = new RecordingSink();
        var handler = new PushDeliveryHandler(
            new StubValidator(error: null, token: BuildToken()),
            new SharedSignalsValidationOptions(),
            sink,
            new FakeReplayCache());

        var first = await handler.HandleAsync(
            SetMediaType, "a.b.c", TestContext.Current.CancellationToken);
        var second = await handler.HandleAsync(
            SetMediaType, "a.b.c", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
        Assert.Single(sink.Consumed);
    }
}
