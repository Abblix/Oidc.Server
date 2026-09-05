// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SecurityEvents.CAEP;
using Abblix.SecurityEvents.Events;
using Xunit;

namespace Abblix.SecurityEvents.RISC.UnitTests;

/// <summary>
/// Pins the payload models to the specification's own examples: every fixture here is the event
/// payload of a figure from RISC 1.0, verbatim, so a drifted wire name - the hyphenated
/// new-value above all - fails against the text both sides of the wire read.
/// </summary>
public class RiscEventFixtureTests
{
    private static IEventPayload Deserialize(string eventType, string payloadJson) =>
        new EventTypeRegistry()
            .RegisterRiscEvents()
            .Deserialize(eventType, JsonNode.Parse(payloadJson)!.AsObject());

    [Fact]
    public void AccountCredentialChangeRequired_Figure1_EmptyPayloadIsValid()
    {
        // RISC 1.0 Section 2.1: the event has no attributes, so Figure 1 carries {}.
        var payload = Deserialize(RiscEventTypes.AccountCredentialChangeRequired, "{}");

        Assert.IsType<AccountCredentialChangeRequiredPayload>(payload);
    }

    [Fact]
    public void AccountDisabled_Figure2_ReadsTheHijackingReason()
    {
        var payload = Deserialize(
            RiscEventTypes.AccountDisabled,
            """
            {
                "reason": "hijacking"
            }
            """);

        var disabled = Assert.IsType<AccountDisabledPayload>(payload);
        Assert.Equal(AccountDisabledPayload.Reasons.Hijacking, disabled.Reason);
    }

    [Fact]
    public void IdentifierChanged_Figure3_ReadsTheHyphenatedNewValue()
    {
        // Section 2.5 spells the claim "new-value" with a hyphen - the one outlier among the
        // underscore-separated claims, and exactly the kind of name a habit would misspell.
        var payload = Deserialize(
            RiscEventTypes.IdentifierChanged,
            """
            {
                "new-value": "john.roe@example.com"
            }
            """);

        var changed = Assert.IsType<IdentifierChangedPayload>(payload);
        Assert.Equal("john.roe@example.com", changed.NewValue);
    }

    [Fact]
    public void IdentifierRecycled_Figure4_EmptyPayloadIsValid()
    {
        var payload = Deserialize(RiscEventTypes.IdentifierRecycled, "{}");

        Assert.IsType<IdentifierRecycledPayload>(payload);
    }

    [Fact]
    public void CredentialCompromise_Figure5_ReadsTheCaepCredentialType()
    {
        // The expected value comes from the CAEP dictionary's constants on purpose: RISC 1.0
        // Section 2.7 defines credential_type by reference to the CAEP Credential Change event,
        // so the two packages must agree on the strings.
        var payload = Deserialize(
            RiscEventTypes.CredentialCompromise,
            """
            {
                "credential_type": "password"
            }
            """);

        var compromise = Assert.IsType<CredentialCompromisePayload>(payload);
        Assert.Equal(CredentialChangePayload.CredentialTypes.Password, compromise.CredentialType);
        Assert.Null(compromise.EventTimestamp);
        Assert.Null(compromise.ReasonAdmin);
        Assert.Null(compromise.ReasonUser);
    }

    [Fact]
    public void TypedWrite_ReproducesTheFigure3Payload()
    {
        var written = JsonSerializer.SerializeToNode(new IdentifierChangedPayload
        {
            NewValue = "john.roe@example.com",
        });

        var expected = JsonNode.Parse(
            """
            {
                "new-value": "john.roe@example.com"
            }
            """);

        Assert.True(JsonNode.DeepEquals(expected, written));
    }

    [Fact]
    public void TypedWrite_ReproducesTheFigure5Payload()
    {
        var written = JsonSerializer.SerializeToNode(new CredentialCompromisePayload
        {
            CredentialType = CredentialChangePayload.CredentialTypes.Password,
        });

        var expected = JsonNode.Parse(
            """
            {
                "credential_type": "password"
            }
            """);

        Assert.True(JsonNode.DeepEquals(expected, written));
    }

    [Fact]
    public void CredentialCompromise_WithDiscoveryTime_TravelsAsUnixSeconds()
    {
        // Section 2.7: event_timestamp is a JSON number of seconds since the epoch - the moment
        // the transmitter DISCOVERED the compromise.
        var discoveredAt = DateTimeOffset.FromUnixTimeSeconds(1508184845);

        var written = JsonSerializer.SerializeToNode(new CredentialCompromisePayload
        {
            CredentialType = CredentialChangePayload.CredentialTypes.Pin,
            EventTimestamp = discoveredAt,
        });

        var wire = Assert.IsType<JsonObject>(written);
        Assert.Equal(1508184845, (long?)wire[RiscClaimNames.EventTimestamp]);

        var readBack = Assert.IsType<CredentialCompromisePayload>(Deserialize(
            RiscEventTypes.CredentialCompromise,
            wire.ToJsonString()));
        Assert.Equal(discoveredAt, readBack.EventTimestamp);
    }
}
