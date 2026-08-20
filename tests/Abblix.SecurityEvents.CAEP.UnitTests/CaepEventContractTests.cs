// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SecurityEvents.Events;
using Xunit;

namespace Abblix.SecurityEvents.CAEP.UnitTests;

/// <summary>
/// Pins the dictionary's contract rather than any one figure: the registration teaches the
/// registry all eight event types at once, a payload missing a REQUIRED member fails loudly, and
/// absent OPTIONAL members stay off the wire instead of travelling as nulls.
/// </summary>
public class CaepEventContractTests
{
    [Fact]
    public void RegisterCaepEvents_TeachesAllEightEventTypes()
    {
        var registry = new EventTypeRegistry().RegisterCaepEvents();

        var expected = new Dictionary<string, Type>
        {
            [CaepEventTypes.SessionRevoked] = typeof(SessionRevokedPayload),
            [CaepEventTypes.TokenClaimsChange] = typeof(TokenClaimsChangePayload),
            [CaepEventTypes.CredentialChange] = typeof(CredentialChangePayload),
            [CaepEventTypes.AssuranceLevelChange] = typeof(AssuranceLevelChangePayload),
            [CaepEventTypes.DeviceComplianceChange] = typeof(DeviceComplianceChangePayload),
            [CaepEventTypes.SessionEstablished] = typeof(SessionEstablishedPayload),
            [CaepEventTypes.SessionPresented] = typeof(SessionPresentedPayload),
            [CaepEventTypes.RiskLevelChange] = typeof(RiskLevelChangePayload),
        };

        Assert.All(expected, pair =>
        {
            Assert.True(registry.TryGetPayloadType(pair.Key, out var payloadType));
            Assert.Equal(pair.Value, payloadType);
        });
    }

    [Fact]
    public void RegisterCaepEvents_Twice_IsRejected()
    {
        // The registry refuses duplicates; registering the dictionary twice is a configuration
        // bug that must surface at startup, not a silent second write.
        var registry = new EventTypeRegistry().RegisterCaepEvents();

        Assert.Throws<ArgumentException>(() => registry.RegisterCaepEvents());
    }

    [Fact]
    public void SessionRevoked_EmptyPayload_IsValid()
    {
        // CAEP 1.0 Section 3.1.1: session-revoked has no event-specific claims and every common
        // claim is OPTIONAL, so the empty object of Figure 3 must deserialize cleanly.
        var payload = new EventTypeRegistry()
            .RegisterCaepEvents()
            .Deserialize(CaepEventTypes.SessionRevoked, new JsonObject());

        var revoked = Assert.IsType<SessionRevokedPayload>(payload);
        Assert.Null(revoked.EventTimestamp);
        Assert.Null(revoked.InitiatingEntity);
        Assert.Null(revoked.ReasonAdmin);
        Assert.Null(revoked.ReasonUser);
    }

    [Theory]
    [InlineData("""{"change_type": "create"}""")]
    [InlineData("""{"credential_type": "password"}""")]
    public void CredentialChange_MissingRequiredMember_FailsLoudly(string payloadJson)
    {
        // CAEP 1.0 Section 3.3.1 makes both credential_type and change_type REQUIRED; a payload
        // without either is a shape disagreement, not a value to default.
        var registry = new EventTypeRegistry().RegisterCaepEvents();

        Assert.ThrowsAny<JsonException>(() => registry.Deserialize(
            CaepEventTypes.CredentialChange,
            JsonNode.Parse(payloadJson)!.AsObject()));
    }

    [Fact]
    public void RiskLevelChange_MissingPrincipal_FailsLoudly()
    {
        // CAEP 1.0 Section 3.8.1 makes principal REQUIRED.
        var registry = new EventTypeRegistry().RegisterCaepEvents();

        Assert.ThrowsAny<JsonException>(() => registry.Deserialize(
            CaepEventTypes.RiskLevelChange,
            JsonNode.Parse("""{"current_level": "LOW"}""")!.AsObject()));
    }

    [Fact]
    public void AbsentOptionalClaims_StayOffTheWire()
    {
        // An absent OPTIONAL claim and a null-valued one are different texts on the wire, and
        // the specification's examples never write nulls - neither may we.
        var written = JsonSerializer.SerializeToNode(new SessionEstablishedPayload
        {
            AuthenticationContextClassReference = "AAL2",
        });

        var wire = Assert.IsType<JsonObject>(written);
        var property = Assert.Single(wire);
        Assert.Equal(CaepClaimNames.Acr, property.Key);
    }
}
