// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.Utils.Json;

namespace Abblix.SharedSignals.Model;

/// <summary>
/// An Event Stream's configuration: the document both sides contribute to and the transmitter
/// returns whole (SSF 1.0 Section 8.1.1). Each member's doc says who supplies it, because that
/// decides who may change it - a receiver's update carries the receiver-supplied members, and a
/// transmitter-supplied member it echoes back must match the expected value exactly, a mismatch
/// earning a 400; only a MISSING transmitter-supplied member is ignored
/// (SSF 1.0 Sections 8.1.1.3, 8.1.1.4).
/// </summary>
/// <remarks>
/// The members SSF 1.0 Section 8.1.1 marks REQUIRED are declared <c>required</c>: this type is
/// the full document a transmitter serializes and a receiver reads back as a client, so a copy
/// missing one of them is malformed in either direction. The receiver-supplied subset a create or
/// update request carries is a different, smaller shape and is not this type.
/// </remarks>
public sealed record StreamConfiguration
{
    /// <summary>
    /// Transmitter-supplied, REQUIRED. The string that uniquely identifies the stream, generated
    /// by the transmitter at stream creation (SSF 1.0 Section 8.1.1).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.StreamId)]
    public required string StreamId { get; init; }

    /// <summary>
    /// Transmitter-supplied, REQUIRED. The transmitter's issuer identifier: an https URL with no
    /// query or fragment, identical to the "iss" claim of every SET issued from this transmitter -
    /// and the value a receiver must confirm matches the issuer it discovered the transmitter
    /// through (SSF 1.0 Sections 8.1.1, 8.1.1.1).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Issuer)]
    public required string Issuer { get; init; }

    /// <summary>
    /// Transmitter-supplied, REQUIRED. The audience identifying the stream's receiver(s), a
    /// string or an array of strings as the JWT "aud" claim defines it; never updated after
    /// creation (SSF 1.0 Section 8.1.1). A single audience travels as a bare string, either form
    /// reads back as the array.
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Audience)]
    [JsonConverter(typeof(SingleOrArrayConverter<string>))]
    public required string[] Audiences { get; init; }

    /// <summary>
    /// Transmitter-supplied, OPTIONAL. The event types the transmitter supports for this
    /// receiver; absent means the set is published some other way, such as documentation
    /// (SSF 1.0 Section 8.1.1).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.EventsSupported)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? EventsSupported { get; init; }

    /// <summary>
    /// Receiver-supplied, OPTIONAL. The event types the receiver asked for - only ones it
    /// understands and can act on; the transmitter ignores values it does not understand
    /// (SSF 1.0 Section 8.1.1).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.EventsRequested)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? EventsRequested { get; init; }

    /// <summary>
    /// Transmitter-supplied, REQUIRED. The event types the transmitter must include in the
    /// stream: a subset of the intersection of the supported and requested sets, and the one
    /// field a receiver relies on to know what to expect (SSF 1.0 Section 8.1.1).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.EventsDelivered)]
    public required IReadOnlyList<string> EventsDelivered { get; init; }

    /// <summary>
    /// REQUIRED. How SETs travel over this stream, dispatched on the "method" member
    /// (SSF 1.0 Sections 8.1.1, 6.1). The one member both sides contribute to: the receiver
    /// proposes it at creation, and for poll delivery the transmitter supplies the endpoint URL.
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Delivery)]
    public required StreamDeliveryMethod Delivery { get; init; }

    /// <summary>
    /// Transmitter-supplied, OPTIONAL. The minimum time between verification requests, carried
    /// as an integer number of seconds; requesting more often may earn a 429
    /// (SSF 1.0 Sections 8.1.1, 8.1.4.2).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.MinVerificationInterval)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public TimeSpan? MinVerificationInterval { get; init; }

    /// <summary>
    /// Receiver-supplied, OPTIONAL. A human-readable description of the stream, useful in
    /// multi-stream systems; the transmitter may truncate it (SSF 1.0 Section 8.1.1).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Description)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Description { get; init; }

    /// <summary>
    /// Transmitter-supplied, OPTIONAL. The stream's refreshable inactivity timeout, carried as
    /// an integer number of seconds. After it passes with no eligible receiver activity the
    /// transmitter may pause, disable or delete the stream, announcing a pause or disable
    /// through a Stream Updated Event (SSF 1.0 Section 8.1.1).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.InactivityTimeout)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public TimeSpan? InactivityTimeout { get; init; }
}
