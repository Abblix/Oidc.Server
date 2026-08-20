// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the stream configuration document against the member names, optionality and value shapes
/// SSF 1.0 Section 8.1.1 fixes.
/// </summary>
public class StreamConfigurationTests
{
    /// <summary>
    /// The create-stream response of SSF 1.0 Section 8.1.1.1, Figure 22, verbatim.
    /// </summary>
    private const string CreateStreamResponseFixture =
        """
        {
            "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
            "iss": "https://tr.example.com",
            "aud": [
                "https://receiver.example.com/web",
                "https://receiver.example.com/mobile"
            ],
            "delivery": {
                "method": "urn:ietf:rfc:8935",
                "endpoint_url": "https://receiver.example.com/events"
            },
            "events_supported": [
                "urn:example:secevent:events:type_1",
                "urn:example:secevent:events:type_2",
                "urn:example:secevent:events:type_3"
            ],
            "events_requested": [
                "urn:example:secevent:events:type_2",
                "urn:example:secevent:events:type_3",
                "urn:example:secevent:events:type_4"
            ],
            "events_delivered": [
                "urn:example:secevent:events:type_2",
                "urn:example:secevent:events:type_3"
            ],
            "description": "Stream for Receiver A using events type_2, type_3, type_4"
        }
        """;

    [Fact]
    public void Configuration_ReadsTheSpecificationFixtureWhole()
    {
        var configuration = JsonSerializer.Deserialize<StreamConfiguration>(CreateStreamResponseFixture);

        Assert.NotNull(configuration);
        Assert.Equal("f67e39a0a4d34d56b3aa1bc4cff0069f", configuration.StreamId);
        Assert.Equal("https://tr.example.com", configuration.Issuer);
        Assert.Equal(
            ["https://receiver.example.com/web", "https://receiver.example.com/mobile"],
            configuration.Audiences);

        var push = Assert.IsType<PushDeliveryMethod>(configuration.Delivery);
        Assert.Equal(new Uri("https://receiver.example.com/events"), push.EndpointUrl);

        Assert.Equal(3, configuration.EventsSupported!.Count);
        Assert.Equal(3, configuration.EventsRequested!.Count);
        Assert.Equal(
            ["urn:example:secevent:events:type_2", "urn:example:secevent:events:type_3"],
            configuration.EventsDelivered);
        Assert.Equal("Stream for Receiver A using events type_2, type_3, type_4", configuration.Description);
        Assert.Null(configuration.MinVerificationInterval);
        Assert.Null(configuration.InactivityTimeout);
    }

    [Fact]
    public void SingleAudience_ReadsFromABareString_AndWritesBackAsOne()
    {
        // "A string or an array of strings" (SSF 1.0 Section 8.1.1): either wire form is legal,
        // and a single audience keeps the compact form on the way out - the JWT "aud" convention.
        var configuration = new StreamConfiguration
        {
            StreamId = "stream-1",
            Issuer = "https://tr.example.com",
            Audiences = ["https://receiver.example.com"],
            EventsDelivered = [],
            Delivery = new PollDeliveryMethod(new Uri("https://tr.example.com/poll/stream-1")),
        };

        var written = JsonNode.Parse(JsonSerializer.Serialize(configuration))!.AsObject();
        Assert.Equal(
            JsonValueKind.String,
            written[StreamMemberNames.Audience]!.GetValueKind());

        var reread = JsonSerializer.Deserialize<StreamConfiguration>(written.ToJsonString());
        Assert.Equal(configuration.Audiences, reread!.Audiences);
    }

    [Fact]
    public void TransmitterTimes_TravelAsIntegerSeconds()
    {
        // min_verification_interval is "an integer ... of time in seconds" and inactivity_timeout
        // shares the expires_in syntax of RFC 6749 Section A.14 (SSF 1.0 Section 8.1.1).
        var configuration = new StreamConfiguration
        {
            StreamId = "stream-1",
            Issuer = "https://tr.example.com",
            Audiences = ["https://receiver.example.com"],
            EventsDelivered = [],
            Delivery = new PollDeliveryMethod(new Uri("https://tr.example.com/poll/stream-1")),
            MinVerificationInterval = TimeSpan.FromMinutes(15),
            InactivityTimeout = TimeSpan.FromDays(7),
        };

        var written = JsonNode.Parse(JsonSerializer.Serialize(configuration))!.AsObject();
        Assert.Equal(900, written[StreamMemberNames.MinVerificationInterval]!.GetValue<long>());
        Assert.Equal(604800, written[StreamMemberNames.InactivityTimeout]!.GetValue<long>());

        var reread = JsonSerializer.Deserialize<StreamConfiguration>(written.ToJsonString());
        Assert.Equal(TimeSpan.FromMinutes(15), reread!.MinVerificationInterval);
        Assert.Equal(TimeSpan.FromDays(7), reread.InactivityTimeout);
    }

    [Fact]
    public void Document_MissingARequiredMember_IsRefused()
    {
        // Every member Section 8.1.1 marks REQUIRED, absent in turn from an otherwise complete
        // document, must refuse to read rather than default into existence.
        var complete = JsonNode.Parse(CreateStreamResponseFixture)!.AsObject();

        foreach (var member in new[]
                 {
                     StreamMemberNames.StreamId,
                     StreamMemberNames.Issuer,
                     StreamMemberNames.Audience,
                     StreamMemberNames.EventsDelivered,
                     StreamMemberNames.Delivery,
                 })
        {
            var document = JsonNode.Parse(complete.ToJsonString())!.AsObject();
            Assert.True(document.Remove(member));

            Assert.Throws<JsonException>(
                () => JsonSerializer.Deserialize<StreamConfiguration>(document.ToJsonString()));
        }
    }
}
