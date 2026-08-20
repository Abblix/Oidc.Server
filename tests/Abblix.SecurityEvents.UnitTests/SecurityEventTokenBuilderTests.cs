// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Subjects;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Pins the builder's contract: what RFC 8417 Section 2.2 requires cannot be omitted, what the
/// profile forbids cannot be written, and what the builder promises about its own mechanics -
/// reusability, the fixed "typ", the clock default - actually holds.
/// </summary>
public class SecurityEventTokenBuilderTests
{
    private static SecurityEventTokenBuilder MinimalValidBuilder() => new SecurityEventTokenBuilder()
        .WithIssuer("https://issuer.example.com")
        .WithJwtId("id-1")
        .WithEvent("https://example.com/events/test");

    [Fact]
    public void Build_WithoutIssuer_Fails()
    {
        var builder = new SecurityEventTokenBuilder()
            .WithJwtId("id-1")
            .WithEvent("https://example.com/events/test");

        var exception = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains(JwtClaimTypes.Issuer, exception.Message);
    }

    [Fact]
    public void Build_WithoutJwtId_Fails()
    {
        var builder = new SecurityEventTokenBuilder()
            .WithIssuer("https://issuer.example.com")
            .WithEvent("https://example.com/events/test");

        var exception = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains(JwtClaimTypes.JwtId, exception.Message);
    }

    [Fact]
    public void Build_WithoutEvents_Fails()
    {
        var builder = new SecurityEventTokenBuilder()
            .WithIssuer("https://issuer.example.com")
            .WithJwtId("id-1");

        var exception = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains(JwtClaimTypes.Events, exception.Message);
    }

    [Fact]
    public void Build_SetsTheSecurityEventTokenType_AndThereIsNoWayToChangeIt()
    {
        // RFC 8417 Section 2.3: explicit typing MUST be included where a SET could be confused
        // with another kind of JWT. The builder has no method touching the header at all, so the
        // guarantee is structural; this test keeps it from silently gaining one.
        var token = MinimalValidBuilder().Build();

        Assert.Equal(SecurityEventToken.TokenType, token.Token.Header.Type);
    }

    [Fact]
    public void Build_DefaultsIssuedAt_ToTheClock()
    {
        // "iat" is REQUIRED (RFC 8417 Section 2.2), so a builder never asked for one still writes
        // it - from the clock the test controls, proving no hidden system-time read.
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1700000000));

        var token = new SecurityEventTokenBuilder(clock)
            .WithIssuer("https://issuer.example.com")
            .WithJwtId("id-1")
            .WithEvent("https://example.com/events/test")
            .Build();

        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1700000000), token.IssuedAt);
    }

    [Fact]
    public void WithClaim_Exp_IsRejected()
    {
        // The absence of "exp" is the wall between a SET and the ID and access tokens an attacker
        // would pass one off as (RFC 8417 Sections 4.1 and 4.2); the builder owns that defence.
        var exception = Assert.Throws<ArgumentException>(
            () => MinimalValidBuilder().WithClaim(JwtClaimTypes.ExpiresAt, 1700000000));

        Assert.Contains("RFC 8417", exception.Message);
    }

    [Theory]
    [InlineData(JwtClaimTypes.Issuer)]
    [InlineData(JwtClaimTypes.Audience)]
    [InlineData(JwtClaimTypes.JwtId)]
    [InlineData(JwtClaimTypes.IssuedAt)]
    [InlineData(JwtClaimTypes.Subject)]
    [InlineData(JwtClaimTypes.Events)]
    [InlineData(IanaClaimTypes.Txn)]
    [InlineData(IanaClaimTypes.Toe)]
    [InlineData(IanaClaimTypes.SubId)]
    public void WithClaim_ManagedClaim_IsRejected_NamingTheRightDoor(string claim)
    {
        var exception = Assert.Throws<ArgumentException>(
            () => MinimalValidBuilder().WithClaim(claim, "value"));

        Assert.Contains("With", exception.Message);
    }

    [Fact]
    public void WithEvent_DuplicateIdentifier_IsRejected()
    {
        // "Multiple event identifiers with the same value MUST NOT be used"
        // (RFC 8417 Section 2.2).
        var builder = MinimalValidBuilder();

        Assert.Throws<ArgumentException>(() => builder.WithEvent("https://example.com/events/test"));
    }

    [Fact]
    public void WithEvent_PayloadTakenFromAnotherToken_IsRejected_NamingTheWayOut()
    {
        // Moving a node between JSON trees is what parsing a token and reusing its payload does. The
        // serializer's own complaint names neither the event nor the remedy, so the collection refuses first.
        var parsed = JsonNode.Parse("""{"events":{"https://example.com/events/other":{"a":1}}}""")!.AsObject();
        var attached = parsed["events"]!["https://example.com/events/other"]!.AsObject();

        var builder = MinimalValidBuilder();

        var exception = Assert.Throws<ArgumentException>(
            () => builder.WithEvent("https://example.com/events/second", attached));

        Assert.Contains(nameof(JsonNode.DeepClone), exception.Message);
    }

    [Fact]
    public void WithEvent_PayloadOfItsOwn_IsAccepted()
    {
        // The other side of the same guard: a payload with no parent is the ordinary case, and a check written
        // to reject "attached" must not reject "absent" along with it.
        var token = MinimalValidBuilder()
            .WithEvent("https://example.com/events/second", new JsonObject { ["a"] = 1 })
            .Build();

        Assert.True(token.Events!.TryGetPayload("https://example.com/events/second", out var payload));
        Assert.Equal(1, payload["a"]!.GetValue<int>());
    }

    [Fact]
    public void WithEvent_WithoutPayload_WritesTheEmptyObject()
    {
        // "An event with no payload claims SHALL be represented as the empty JSON object"
        // (RFC 8417 Section 2).
        var token = MinimalValidBuilder().Build();

        var events = token.Events;
        Assert.NotNull(events);
        Assert.True(events.TryGetPayload("https://example.com/events/test", out var payload));
        Assert.Empty(payload);
    }

    [Fact]
    public void OptionalClaims_AreAbsent_NotNull()
    {
        // An empty "aud" is not a claim about audiences and a null "txn" is not a transaction:
        // the wire distinguishes an absent member from a null one, so the builder must too.
        var payload = MinimalValidBuilder().Build().Token.Payload.Json;

        Assert.False(payload.ContainsKey(IanaClaimTypes.Aud));
        Assert.False(payload.ContainsKey(IanaClaimTypes.Sub));
        Assert.False(payload.ContainsKey(IanaClaimTypes.Txn));
        Assert.False(payload.ContainsKey(IanaClaimTypes.Toe));
        Assert.False(payload.ContainsKey(IanaClaimTypes.SubId));
    }

    [Fact]
    public void SubjectId_RoundTrips_ThroughTheModel()
    {
        // The "sub_id" claim carries a Subject Identifier object (RFC 9493 Section 4.2); the
        // reader dispatches on its "format" and hands back the typed subtype.
        var token = MinimalValidBuilder()
            .WithSubjectId(new OpaqueSubject("f67e39a0a4d34d56b3aa1bc4cff0069f"))
            .Build();

        var subjectId = Assert.IsType<OpaqueSubject>(token.GetSubjectId());
        Assert.Equal("f67e39a0a4d34d56b3aa1bc4cff0069f", subjectId.Id);
    }

    [Fact]
    public void TransactionAndTimeOfEvent_RoundTrip_ThroughTheModel()
    {
        var timeOfEvent = DateTimeOffset.FromUnixTimeSeconds(1754040000);

        var token = MinimalValidBuilder()
            .WithTransactionId("txn-123")
            .WithTimeOfEvent(timeOfEvent)
            .Build();

        Assert.Equal("txn-123", token.TransactionId);
        Assert.Equal(timeOfEvent, token.TimeOfEvent);
    }

    [Fact]
    public void Build_Twice_YieldsIndependentTokens()
    {
        // The builder is documented as reusable: a JsonNode belongs to one document, so without
        // deep cloning the second build would steal the first token's nodes.
        var builder = MinimalValidBuilder()
            .WithClaim("custom", new JsonObject { ["value"] = 1 });

        var first = builder.Build();
        var second = builder.Build();

        // Mutating one token must not reach the other.
        first.Token.Payload.Json.Remove(JwtClaimTypes.Events);

        Assert.NotNull(second.Events);
        Assert.Single(second.Events);
        Assert.True(JsonNode.DeepEquals(
            new JsonObject { ["value"] = 1 },
            second.Token.Payload.Json["custom"]));
    }

    [Fact]
    public void EventsCollection_RefusesToEnumerate_ANonObjectPayload()
    {
        // The view refuses to invent a payload for a statement RFC 8417 Section 2.2 forbids:
        // enumeration is where a wire-read malformation would otherwise slip into typed code.
        var events = new EventsCollection(
            new JsonObject { ["urn:example:event"] = "not-an-object" });

        Assert.Throws<InvalidOperationException>(() => events.ToArray());
    }

    [Fact]
    public void WithClaim_WritingTheSameNameTwice_IsRejected()
    {
        // Custom claims obey the same one-writer rule the managed claims enforce: without this,
        // the second write would win silently at Build and the first would vanish without trace.
        var builder = new SecurityEventTokenBuilder().WithClaim("acr", "urn:example:low");

        var error = Assert.Throws<ArgumentException>(() => builder.WithClaim("acr", "urn:example:high"));

        Assert.Contains("already written", error.Message);
    }

    [Fact]
    public void EventsCollection_RefusesAPayloadAttachedToAnotherTree()
    {
        // Handing over a node still parented in a parsed document would otherwise surface as the
        // serializer's own "already has a parent", naming neither the event nor the way out.
        var parsed = (JsonObject)JsonNode.Parse("""{"payload":{"change":"revoked"}}""")!;
        var attached = (JsonObject)parsed["payload"]!;

        var error = Assert.Throws<ArgumentException>(
            () => new EventsCollection().Add("urn:example:event", attached));

        Assert.Contains(nameof(JsonNode.DeepClone), error.Message);
    }

    [Fact]
    public void Events_RepeatedReads_ShareOneView()
    {
        var token = MinimalValidBuilder().Build();

        Assert.Same(token.Events, token.Events);
    }

    [Fact]
    public async Task SignAsync_HandsTheBuiltTokenToTheSigner()
    {
        var signer = new CapturingSigner();

        var compact = await MinimalValidBuilder()
            .SignAsync(signer, TestContext.Current.CancellationToken);

        Assert.Equal(CapturingSigner.Result, compact);
        Assert.NotNull(signer.Signed);
        Assert.Equal("https://issuer.example.com", signer.Signed.Issuer);
        Assert.Equal(SecurityEventToken.TokenType, signer.Signed.Token.Header.Type);
    }

    /// <summary>
    /// A signer that records what it was asked to sign: the test is about the handoff, and real
    /// cryptography would only obscure whose behaviour failed.
    /// </summary>
    private sealed class CapturingSigner : ISecurityEventTokenSigner
    {
        public const string Result = "header.payload.signature";

        public SecurityEventToken? Signed { get; private set; }

        public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
        {
            Signed = token;
            return Task.FromResult(Result);
        }
    }
}
