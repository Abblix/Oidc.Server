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
