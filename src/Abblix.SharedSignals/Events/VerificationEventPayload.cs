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
/// The payload of the Verification Event (SSF 1.0 Section 8.1.4.1). The SET carrying it names
/// the stream in its top-level "sub_id" - an opaque identifier whose id is the stream's - and
/// the receiver confirms the "state" value matches what it sent, answering "invalid_state" to
/// the delivery when it does not.
/// </summary>
public sealed record VerificationEventPayload : IEventPayload
{
    /// <summary>
    /// OPTIONAL. The opaque value the receiver provided when it triggered the event, echoed
    /// back for correlation; absent when the transmitter initiated the verification itself
    /// (SSF 1.0 Sections 8.1.4.1, 8.1.4.2).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.State)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? State { get; init; }
}
