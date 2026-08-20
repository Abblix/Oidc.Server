// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;
using Abblix.SharedSignals.Model.Delivery;

namespace Abblix.SharedSignals.Model;

/// <summary>
/// The body of a receiver's request to create an Event Stream: exactly the receiver-supplied
/// members of the stream configuration, every one optional (SSF 1.0 Section 8.1.1.1). An empty
/// body is well-formed - a transmitter reads a missing delivery as poll, and one that supports
/// poll delivery answers with its own endpoint URL; one that does not may answer 400, so a
/// caller should consult the advertised "delivery_methods_supported" first.
/// </summary>
public sealed record CreateStreamRequest
{
    /// <summary>
    /// OPTIONAL. The event types the receiver asks for - only ones it understands and can act
    /// on; the transmitter ignores values it does not understand (SSF 1.0 Section 8.1.1).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.EventsRequested)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? EventsRequested { get; init; }

    /// <summary>
    /// OPTIONAL. The delivery method the receiver proposes. Absent means poll: the transmitter
    /// assumes "urn:ietf:rfc:8936", and one that supports poll answers with a delivery object
    /// carrying its own endpoint URL - while one that does not support the method may answer
    /// 400 (SSF 1.0 Section 8.1.1.1).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Delivery)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public StreamDeliveryMethod? Delivery { get; init; }

    /// <summary>
    /// OPTIONAL. A human-readable description of the stream (SSF 1.0 Section 8.1.1).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Description)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Description { get; init; }
}
