// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SharedSignals.Events;
using Abblix.SharedSignals.Model;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the payloads of the framework's own events - verification (SSF 1.0 Section 8.1.4.1) and
/// stream-updated (Section 8.1.5) - against the specification's figures.
/// </summary>
public class SharedSignalsEventPayloadTests
{
    [Fact]
    public void VerificationPayload_RoundTripsTheFigureState()
    {
        // The payload of the Verification SET in Figure 46.
        var payload = JsonSerializer.Deserialize<VerificationEventPayload>(
            """{"state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo="}""");

        Assert.NotNull(payload);
        Assert.Equal("VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo=", payload.State);
    }

    [Fact]
    public void VerificationPayload_WithoutState_WritesTheEmptyObject()
    {
        // A transmitter-initiated verification carries no "state" (Section 8.1.4.2), and an
        // absent member must not travel as null.
        var written = JsonNode.Parse(
            JsonSerializer.Serialize(new VerificationEventPayload()))!.AsObject();

        Assert.Empty(written);
    }

    [Fact]
    public void StreamUpdatedPayload_ReadsTheSpecificationFixture()
    {
        // The payload of the Stream Updated SET in Figure 47.
        var payload = JsonSerializer.Deserialize<StreamUpdatedEventPayload>(
            """{"status": "paused", "reason": "Internal error"}""");

        Assert.NotNull(payload);
        Assert.Equal(StreamStatuses.Paused, payload.Status);
        Assert.Equal("Internal error", payload.Reason);
    }

    [Fact]
    public void StreamUpdatedPayload_MissingTheStatus_IsRefused()
    {
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<StreamUpdatedEventPayload>(
                """{"reason": "Internal error"}"""));
    }
}
