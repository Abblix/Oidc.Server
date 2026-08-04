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

using System.Text.Json;
using Abblix.SharedSignals.Model.Delivery;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the polymorphic delivery object against the wire shapes SSF 1.0 Section 6.1 fixes: the
/// "method" member decides the concrete type, push and poll carry their own members, and an
/// unknown method is refused rather than carried around half-parsed.
/// </summary>
public class StreamDeliveryMethodTests
{
    /// <summary>
    /// The delivery object of the create-stream example (SSF 1.0 Section 8.1.1.1, Figure 21).
    /// </summary>
    private const string PushFixture =
        """
        {
            "method": "urn:ietf:rfc:8935",
            "endpoint_url": "https://receiver.example.com/events"
        }
        """;

    [Fact]
    public void PushDelivery_ReadsFromTheSpecificationFixture()
    {
        var delivery = JsonSerializer.Deserialize<StreamDeliveryMethod>(PushFixture);

        var push = Assert.IsType<PushDeliveryMethod>(delivery);
        Assert.Equal("urn:ietf:rfc:8935", push.Method);
        Assert.Equal(new Uri("https://receiver.example.com/events"), push.EndpointUrl);
        Assert.Null(push.AuthorizationHeader);
    }

    [Fact]
    public void PushDelivery_RoundTrips_WithAuthorizationHeader()
    {
        var original = new PushDeliveryMethod(new Uri("https://receiver.example.com/events"))
        {
            AuthorizationHeader = "Bearer opaque-value",
        };

        var json = JsonSerializer.Serialize<StreamDeliveryMethod>(original);
        var reread = Assert.IsType<PushDeliveryMethod>(JsonSerializer.Deserialize<StreamDeliveryMethod>(json));

        Assert.Equal(original.EndpointUrl, reread.EndpointUrl);
        Assert.Equal(original.AuthorizationHeader, reread.AuthorizationHeader);
    }

    [Fact]
    public void PollDelivery_RoundTrips_AndCarriesTheTransmitterSuppliedUrl()
    {
        var original = new PollDeliveryMethod(new Uri("https://transmitter.example.com/ssf/poll/stream-1"));

        var json = JsonSerializer.Serialize<StreamDeliveryMethod>(original);
        var reread = Assert.IsType<PollDeliveryMethod>(JsonSerializer.Deserialize<StreamDeliveryMethod>(json));

        Assert.Equal("urn:ietf:rfc:8936", reread.Method);
        Assert.Equal(original.EndpointUrl, reread.EndpointUrl);
    }

    [Fact]
    public void UnknownMethod_IsRefused()
    {
        var error = Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<StreamDeliveryMethod>(
            """{"method": "urn:example:carrier-pigeon", "endpoint_url": "https://x.example.com"}"""));

        Assert.Contains("urn:example:carrier-pigeon", error.Message);
    }

    [Fact]
    public void MissingMethod_IsRefusedNamingTheMember()
    {
        var error = Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<StreamDeliveryMethod>(
            """{"endpoint_url": "https://x.example.com"}"""));

        Assert.Contains("method", error.Message);
    }

    [Fact]
    public void NonObjectDelivery_IsRefused()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<StreamDeliveryMethod>("\"push\""));
    }

    [Fact]
    public void PollProposal_WithoutEndpointUrl_RoundTrips()
    {
        // The poll endpoint URL is transmitter-supplied (SSF 1.0 Section 6.1.2), so a receiver
        // proposing poll sends the bare method - the shape must be constructible and readable.
        var written = JsonSerializer.Serialize<StreamDeliveryMethod>(new PollDeliveryMethod());
        Assert.Equal($$"""{"method":"{{PollDeliveryMethod.MethodUri}}"}""", written);

        var reread = Assert.IsType<PollDeliveryMethod>(
            JsonSerializer.Deserialize<StreamDeliveryMethod>(written));
        Assert.Null(reread.EndpointUrl);
    }

    [Fact]
    public void NonStringMethod_IsRefusedAsMalformedJson()
    {
        // Every malformation of a delivery object must surface as JsonException, so a
        // transmitter mapping parse failures to a 400 never answers 500 for this one shape.
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<StreamDeliveryMethod>(
            """{"method": 42}"""));
    }

    [Fact]
    public void PushWithoutEndpointUrl_IsRefusedAsMalformedJson()
    {
        // The push endpoint URL is receiver-supplied and required; its constructor verdict is
        // re-labelled to the serializer's own exception type at the converter boundary.
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<StreamDeliveryMethod>(
            $$"""{"method": "{{PushDeliveryMethod.MethodUri}}"}"""));
    }
}
