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
/// Pins the dictionary's contract rather than any one figure: the registration teaches the
/// registry all fourteen event types at once - the deprecated one included, since receivers
/// still meet it on the wire - and both dictionaries compose on one registry.
/// </summary>
public class RiscEventContractTests
{
    [Fact]
    public void RegisterRiscEvents_TeachesAllFourteenEventTypes()
    {
        var registry = new EventTypeRegistry().RegisterRiscEvents();

        var expected = new Dictionary<string, Type>
        {
            [RiscEventTypes.AccountCredentialChangeRequired] = typeof(AccountCredentialChangeRequiredPayload),
            [RiscEventTypes.AccountPurged] = typeof(AccountPurgedPayload),
            [RiscEventTypes.AccountDisabled] = typeof(AccountDisabledPayload),
            [RiscEventTypes.AccountEnabled] = typeof(AccountEnabledPayload),
            [RiscEventTypes.IdentifierChanged] = typeof(IdentifierChangedPayload),
            [RiscEventTypes.IdentifierRecycled] = typeof(IdentifierRecycledPayload),
            [RiscEventTypes.CredentialCompromise] = typeof(CredentialCompromisePayload),
            [RiscEventTypes.OptIn] = typeof(OptInPayload),
            [RiscEventTypes.OptOutInitiated] = typeof(OptOutInitiatedPayload),
            [RiscEventTypes.OptOutCancelled] = typeof(OptOutCancelledPayload),
            [RiscEventTypes.OptOutEffective] = typeof(OptOutEffectivePayload),
            [RiscEventTypes.RecoveryActivated] = typeof(RecoveryActivatedPayload),
            [RiscEventTypes.RecoveryInformationChanged] = typeof(RecoveryInformationChangedPayload),
            [RiscEventTypes.SessionsRevoked] = typeof(SessionsRevokedPayload),
        };

        Assert.All(expected, pair =>
        {
            Assert.True(registry.TryGetPayloadType(pair.Key, out var payloadType));
            Assert.Equal(pair.Value, payloadType);
        });
    }

    [Fact]
    public void RegisterRiscEvents_Twice_IsRejected()
    {
        var registry = new EventTypeRegistry().RegisterRiscEvents();

        Assert.Throws<ArgumentException>(() => registry.RegisterRiscEvents());
    }

    [Fact]
    public void CaepAndRiscDictionaries_ComposeOnOneRegistry()
    {
        // A receiver of both profiles registers both dictionaries over the same registry; the
        // URI spaces are disjoint, so nothing collides.
        var registry = new EventTypeRegistry()
            .RegisterCaepEvents()
            .RegisterRiscEvents();

        Assert.True(registry.TryGetPayloadType(CaepEventTypes.SessionRevoked, out _));
        Assert.True(registry.TryGetPayloadType(RiscEventTypes.SessionsRevoked, out _));
    }

    [Fact]
    public void CredentialCompromise_MissingRequiredCredentialType_FailsLoudly()
    {
        // RISC 1.0 Section 2.7 makes credential_type REQUIRED; a payload without it is a shape
        // disagreement, not a value to default.
        var registry = new EventTypeRegistry().RegisterRiscEvents();

        Assert.ThrowsAny<JsonException>(() => registry.Deserialize(
            RiscEventTypes.CredentialCompromise,
            new JsonObject()));
    }

    [Fact]
    public void AbsentOptionalClaims_StayOffTheWire()
    {
        // An absent OPTIONAL claim and a null-valued one are different texts on the wire, and
        // the specification's examples never write nulls - neither may we.
        var written = JsonSerializer.SerializeToNode(new AccountDisabledPayload());

        var wire = Assert.IsType<JsonObject>(written);
        Assert.Empty(wire);
    }
}
