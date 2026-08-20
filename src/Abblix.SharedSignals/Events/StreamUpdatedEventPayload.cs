// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
