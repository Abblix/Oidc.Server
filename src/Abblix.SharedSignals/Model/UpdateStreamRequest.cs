// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;
using Abblix.SharedSignals.Model.Delivery;

namespace Abblix.SharedSignals.Model;

/// <summary>
/// The body of a receiver's request to update or replace an Event Stream's configuration: the
/// stream's identifier plus the receiver-supplied members. One shape serves both verbs, whose
/// difference is entirely in what ABSENCE means - under PATCH an absent member stays unchanged
/// (SSF 1.0 Section 8.1.1.3), under PUT it is a request to delete, which is why PUT demands the
/// full receiver-supplied set (Section 8.1.1.4).
/// </summary>
public sealed record UpdateStreamRequest
{
    /// <summary>
    /// REQUIRED. The stream being updated (SSF 1.0 Sections 8.1.1.3, 8.1.1.4).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.StreamId)]
    public required string StreamId { get; init; }

    /// <summary>
    /// The event types the receiver asks for; when included it should not be an empty array
    /// (SSF 1.0 Sections 8.1.1.3, 8.1.1.4).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.EventsRequested)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? EventsRequested { get; init; }

    /// <summary>
    /// The delivery method the receiver proposes.
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Delivery)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public StreamDeliveryMethod? Delivery { get; init; }

    /// <summary>
    /// A human-readable description of the stream.
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Description)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Description { get; init; }
}
