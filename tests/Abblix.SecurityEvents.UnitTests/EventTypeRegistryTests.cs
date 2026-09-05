// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Abblix.SecurityEvents.Events;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Pins the registry's two-sided contract: a known event type deserializes into its registered
/// model and fails loudly when malformed, while an unknown type rides through as raw JSON - the
/// forward-compatibility rule that keeps a receiver alive when its stream evolves first.
/// </summary>
public class EventTypeRegistryTests
{
    private const string MembershipChanged = "https://tenant.example.com/events/membership-changed";

    private sealed class MembershipChangedPayload : IEventPayload
    {
        [JsonPropertyName("tenant_id")]
        public string? TenantId { get; init; }

        [JsonPropertyName("change")]
        public string? Change { get; init; }
    }

    private static EventTypeRegistry RegistryWithMembershipChanged()
    {
        var registry = new EventTypeRegistry();
        registry.Register<MembershipChangedPayload>(MembershipChanged);
        return registry;
    }

    [Fact]
    public void RegisteredType_DeserializesIntoItsModel()
    {
        var payload = RegistryWithMembershipChanged().Deserialize(
            MembershipChanged,
            new JsonObject { ["tenant_id"] = "t-acme", ["change"] = "revoked" });

        var typed = Assert.IsType<MembershipChangedPayload>(payload);
        Assert.Equal("t-acme", typed.TenantId);
        Assert.Equal("revoked", typed.Change);
    }

    [Fact]
    public void UnregisteredType_RidesThroughAsRawJson()
    {
        // A transmitter may emit a new event type before this receiver updates; rejecting it
        // would make the receiver go deaf exactly when the stream evolves.
        var raw = new JsonObject { ["anything"] = 42 };

        var payload = new EventTypeRegistry().Deserialize("https://example.com/events/new", raw);

        var unknown = Assert.IsType<UnknownEventPayload>(payload);
        Assert.Same(raw, unknown.Json);
    }

    [Fact]
    public void DuplicateRegistration_IsRejected()
    {
        var registry = RegistryWithMembershipChanged();

        var exception = Assert.Throws<ArgumentException>(
            () => registry.Register<MembershipChangedPayload>(MembershipChanged));

        Assert.Contains(MembershipChanged, exception.Message);
    }

    [Fact]
    public void MalformedPayloadOfAKnownType_FailsLoudly()
    {
        // Unlike an unknown type, a malformed payload of a KNOWN type means the transmitter and
        // receiver disagree about a shape both claim to know - silence here would hide a real
        // interoperability break.
        Assert.ThrowsAny<JsonException>(
            () => RegistryWithMembershipChanged().Deserialize(
                MembershipChanged,
                new JsonObject { ["tenant_id"] = new JsonObject() }));
    }

    [Fact]
    public void TypedWithEvent_SerializesThePayloadIntoTheStatement()
    {
        var token = new SecurityEventTokenBuilder()
            .WithIssuer("https://tenant.example.com")
            .WithJwtId("id-1")
            .WithEvent(MembershipChanged, new MembershipChangedPayload { TenantId = "t-acme", Change = "revoked" })
            .Build();

        var events = token.Events;
        Assert.NotNull(events);
        Assert.True(events.TryGetPayload(MembershipChanged, out var payload));
        Assert.True(JsonNode.DeepEquals(
            new JsonObject { ["tenant_id"] = "t-acme", ["change"] = "revoked" },
            payload));
    }

    [Fact]
    public void TypedWithEvent_OfAnUnknownPayload_RetransmitsTheOriginalJson()
    {
        // Forwarding an event a receiver did not recognise must put the EVENT's JSON back on the
        // wire, not a serialization of the passthrough wrapper.
        var original = new JsonObject { ["anything"] = 42 };
        var unknown = new UnknownEventPayload(original);

        var token = new SecurityEventTokenBuilder()
            .WithIssuer("https://tenant.example.com")
            .WithJwtId("id-1")
            .WithEvent("https://example.com/events/new", unknown)
            .Build();

        var events = token.Events;
        Assert.NotNull(events);
        Assert.True(events.TryGetPayload("https://example.com/events/new", out var payload));
        Assert.True(JsonNode.DeepEquals(original, payload));
    }

    [Fact]
    public void RegistryRoundTrip_TypedPayload_SurvivesTheWire()
    {
        // Transmitter and receiver joined: what the typed WithEvent writes, Deserialize reads
        // back into the same model.
        var token = new SecurityEventTokenBuilder()
            .WithIssuer("https://tenant.example.com")
            .WithJwtId("id-1")
            .WithEvent(MembershipChanged, new MembershipChangedPayload { TenantId = "t-acme", Change = "revoked" })
            .Build();

        var events = token.Events;
        Assert.NotNull(events);
        Assert.True(events.TryGetPayload(MembershipChanged, out var wirePayload));

        var received = RegistryWithMembershipChanged().Deserialize(MembershipChanged, wirePayload);

        var typed = Assert.IsType<MembershipChangedPayload>(received);
        Assert.Equal("t-acme", typed.TenantId);
        Assert.Equal("revoked", typed.Change);
    }
}
