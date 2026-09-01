// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
