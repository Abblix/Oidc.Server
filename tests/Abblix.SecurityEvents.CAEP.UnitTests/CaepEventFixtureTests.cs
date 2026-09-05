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
/// Pins the payload models to the specification's own examples: every fixture here is the event
/// payload of a figure from CAEP 1.0, verbatim, so a drifted wire name or a mistyped member fails
/// against the text both sides of the wire read.
/// </summary>
public class CaepEventFixtureTests
{
    /// <summary>The moment every example in CAEP 1.0 stamps into event_timestamp.</summary>
    private static readonly DateTimeOffset FixtureTimestamp = DateTimeOffset.FromUnixTimeSeconds(1615304991);

    private static IEventPayload Deserialize(string eventType, string payloadJson) =>
        new EventTypeRegistry()
            .RegisterCaepEvents()
            .Deserialize(eventType, JsonNode.Parse(payloadJson)!.AsObject());

    [Fact]
    public void SessionRevoked_Figure4_CarriesTheCommonOptionalClaims()
    {
        var payload = Deserialize(
            CaepEventTypes.SessionRevoked,
            """
            {
                "initiating_entity": "policy",
                "reason_admin": {
                    "en": "Landspeed Policy Violation: C076E82F"
                },
                "reason_user": {
                    "en": "Access attempt from multiple regions.",
                    "es-410": "Intento de acceso desde varias regiones."
                },
                "event_timestamp": 1615304991
            }
            """);

        var revoked = Assert.IsType<SessionRevokedPayload>(payload);
        Assert.Equal(CaepEventPayload.InitiatingEntities.Policy, revoked.InitiatingEntity);
        Assert.Equal(FixtureTimestamp, revoked.EventTimestamp);
        Assert.NotNull(revoked.ReasonAdmin);
        Assert.Equal("Landspeed Policy Violation: C076E82F", revoked.ReasonAdmin["en"]);
        Assert.NotNull(revoked.ReasonUser);
        Assert.Equal("Access attempt from multiple regions.", revoked.ReasonUser["en"]);
        Assert.Equal("Intento de acceso desde varias regiones.", revoked.ReasonUser["es-410"]);
    }

    [Fact]
    public void TokenClaimsChange_Figure6_ReadsTheChangedClaims()
    {
        var payload = Deserialize(
            CaepEventTypes.TokenClaimsChange,
            """
            {
                "event_timestamp": 1615304991,
                "claims": {
                    "role": "ro-admin"
                }
            }
            """);

        var change = Assert.IsType<TokenClaimsChangePayload>(payload);
        Assert.Equal(FixtureTimestamp, change.EventTimestamp);
        Assert.Equal("ro-admin", (string?)change.Claims["role"]);
    }

    [Fact]
    public void TokenClaimsChange_Figure8_KeepsSamlClaimUrisAsKeys()
    {
        // A SAML attribute name is a full URI; the claims object must carry it untouched.
        var payload = Deserialize(
            CaepEventTypes.TokenClaimsChange,
            """
            {
                "event_timestamp": 1615304991,
                "claims": {
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role": "ro-admin"
                }
            }
            """);

        var change = Assert.IsType<TokenClaimsChangePayload>(payload);
        Assert.Equal(
            "ro-admin",
            (string?)change.Claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role"]);
    }

    [Fact]
    public void CredentialChange_Figure9_ReadsTheFido2Enrollment()
    {
        var payload = Deserialize(
            CaepEventTypes.CredentialChange,
            """
            {
                "credential_type": "fido2-roaming",
                "change_type": "create",
                "fido2_aaguid": "accced6a-63f5-490a-9eea-e59bc1896cfc",
                "friendly_name": "Jane's USB authenticator",
                "initiating_entity": "user",
                "reason_admin": {
                    "en": "User self-enrollment"
                },
                "event_timestamp": 1615304991
            }
            """);

        var change = Assert.IsType<CredentialChangePayload>(payload);
        Assert.Equal(CredentialChangePayload.CredentialTypes.Fido2Roaming, change.CredentialType);
        Assert.Equal(CredentialChangePayload.ChangeTypes.Create, change.ChangeType);
        Assert.Equal("accced6a-63f5-490a-9eea-e59bc1896cfc", change.Fido2Aaguid);
        Assert.Equal("Jane's USB authenticator", change.FriendlyName);
        Assert.Equal(CaepEventPayload.InitiatingEntities.User, change.InitiatingEntity);
        Assert.Equal(FixtureTimestamp, change.EventTimestamp);
    }

    [Fact]
    public void AssuranceLevelChange_Figure10_ReadsTheNistIncrease()
    {
        var payload = Deserialize(
            CaepEventTypes.AssuranceLevelChange,
            """
            {
                "namespace": "NIST-AAL",
                "current_level": "nist-aal2",
                "previous_level": "nist-aal1",
                "change_direction": "increase",
                "initiating_entity": "user",
                "event_timestamp": 1615304991
            }
            """);

        var change = Assert.IsType<AssuranceLevelChangePayload>(payload);
        Assert.Equal(AssuranceLevelChangePayload.Namespaces.NistAal, change.Namespace);
        Assert.Equal("nist-aal2", change.CurrentLevel);
        Assert.Equal("nist-aal1", change.PreviousLevel);
        Assert.Equal(AssuranceLevelChangePayload.ChangeDirections.Increase, change.ChangeDirection);
    }

    [Fact]
    public void AssuranceLevelChange_Figure11_CustomNamespaceWithoutPreviousLevel()
    {
        // Section 3.4.1: an omitted previous_level means the transmitter does not know it, and
        // the namespace set is open - "Retinal Scan" is a custom alias, not an error.
        var payload = Deserialize(
            CaepEventTypes.AssuranceLevelChange,
            """
            {
                "namespace": "Retinal Scan",
                "current_level": "hi-res-scan",
                "initiating_entity": "user",
                "event_timestamp": 1615304991
            }
            """);

        var change = Assert.IsType<AssuranceLevelChangePayload>(payload);
        Assert.Equal("Retinal Scan", change.Namespace);
        Assert.Equal("hi-res-scan", change.CurrentLevel);
        Assert.Null(change.PreviousLevel);
        Assert.Null(change.ChangeDirection);
    }

    [Fact]
    public void DeviceComplianceChange_Figure12_ReadsBothStatuses()
    {
        var payload = Deserialize(
            CaepEventTypes.DeviceComplianceChange,
            """
            {
                "current_status": "not-compliant",
                "previous_status": "compliant",
                "initiating_entity": "policy",
                "reason_admin": {
                    "en": "Location Policy Violation: C076E8A3"
                },
                "reason_user": {
                    "en": "Device is no longer in a trusted location."
                },
                "event_timestamp": 1615304991
            }
            """);

        var change = Assert.IsType<DeviceComplianceChangePayload>(payload);
        Assert.Equal(DeviceComplianceChangePayload.ComplianceStatuses.Compliant, change.PreviousStatus);
        Assert.Equal(DeviceComplianceChangePayload.ComplianceStatuses.NotCompliant, change.CurrentStatus);
    }

    [Fact]
    public void SessionEstablished_Section362_ReadsTheSessionQualities()
    {
        var payload = Deserialize(
            CaepEventTypes.SessionEstablished,
            """
            {
                "fp_ua": "abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611",
                "acr": "AAL2",
                "amr": ["otp"],
                "event_timestamp": 1615304991
            }
            """);

        var established = Assert.IsType<SessionEstablishedPayload>(payload);
        Assert.Equal("abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611", established.FingerprintUserAgent);
        Assert.Equal("AAL2", established.AuthenticationContextClassReference);
        Assert.NotNull(established.AuthenticationMethodsReferences);
        Assert.Equal("otp", Assert.Single(established.AuthenticationMethodsReferences));
        Assert.Null(established.ExternalId);
    }

    [Fact]
    public void SessionPresented_Section372_ReadsTheCorrelationId()
    {
        var payload = Deserialize(
            CaepEventTypes.SessionPresented,
            """
            {
                "fp_ua": "abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611",
                "ext_id": "12345",
                "event_timestamp": 1615304991
            }
            """);

        var presented = Assert.IsType<SessionPresentedPayload>(payload);
        Assert.Equal("abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611", presented.FingerprintUserAgent);
        Assert.Equal("12345", presented.ExternalId);
    }

    [Fact]
    public void RiskLevelChange_Section382_ReadsTheBreachSignal()
    {
        var payload = Deserialize(
            CaepEventTypes.RiskLevelChange,
            """
            {
                "current_level": "LOW",
                "previous_level": "HIGH",
                "event_timestamp": 1615304991,
                "principal": "USER",
                "risk_reason": "PASSWORD_FOUND_IN_DATA_BREACH"
            }
            """);

        var change = Assert.IsType<RiskLevelChangePayload>(payload);
        Assert.Equal(RiskLevelChangePayload.Principals.User, change.Principal);
        Assert.Equal(RiskLevelChangePayload.RiskLevels.Low, change.CurrentLevel);
        Assert.Equal(RiskLevelChangePayload.RiskLevels.High, change.PreviousLevel);
        Assert.Equal("PASSWORD_FOUND_IN_DATA_BREACH", change.RiskReason);
    }

    [Fact]
    public void TypedWrite_ReproducesTheFigure6Payload()
    {
        // The transmitter direction against the same fixture: what a receiver reads back from the
        // model must be the specification's own JSON, byte-for-byte in content.
        var written = JsonSerializer.SerializeToNode(new TokenClaimsChangePayload
        {
            EventTimestamp = FixtureTimestamp,
            Claims = new JsonObject { ["role"] = "ro-admin" },
        });

        var expected = JsonNode.Parse(
            """
            {
                "event_timestamp": 1615304991,
                "claims": {
                    "role": "ro-admin"
                }
            }
            """);

        Assert.True(JsonNode.DeepEquals(expected, written));
    }

    [Fact]
    public void TypedWrite_ReproducesTheFigure10Payload()
    {
        var written = JsonSerializer.SerializeToNode(new AssuranceLevelChangePayload
        {
            Namespace = AssuranceLevelChangePayload.Namespaces.NistAal,
            CurrentLevel = "nist-aal2",
            PreviousLevel = "nist-aal1",
            ChangeDirection = AssuranceLevelChangePayload.ChangeDirections.Increase,
            InitiatingEntity = CaepEventPayload.InitiatingEntities.User,
            EventTimestamp = FixtureTimestamp,
        });

        var expected = JsonNode.Parse(
            """
            {
                "namespace": "NIST-AAL",
                "current_level": "nist-aal2",
                "previous_level": "nist-aal1",
                "change_direction": "increase",
                "initiating_entity": "user",
                "event_timestamp": 1615304991
            }
            """);

        Assert.True(JsonNode.DeepEquals(expected, written));
    }
}
