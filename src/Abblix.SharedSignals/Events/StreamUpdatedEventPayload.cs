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

using System.Text.Json.Serialization;
using Abblix.SecurityEvents.Events;
using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Events;

/// <summary>
/// The payload of the Stream Updated Event (SSF 1.0 Section 8.1.5): the transmitter's
/// announcement that it changed a stream's status on its own. The SET carrying it names the
/// stream in its top-level "sub_id", an opaque identifier whose id is the stream's.
/// </summary>
public sealed record StreamUpdatedEventPayload : IEventPayload
{
    /// <summary>
    /// REQUIRED. The stream's new status, one of <see cref="StreamStatuses"/>
    /// (SSF 1.0 Section 8.1.5).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Status)]
    public required string Status { get; init; }

    /// <summary>
    /// OPTIONAL. Why the transmitter updated the status (SSF 1.0 Section 8.1.5).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Reason)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Reason { get; init; }
}
