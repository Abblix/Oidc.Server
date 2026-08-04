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
using Abblix.SecurityEvents.Caep;
using Abblix.SecurityEvents.Events;
using Abblix.Utils.Json;

namespace Abblix.SecurityEvents.Risc;

/// <summary>
/// Credential Compromise (RISC 1.0 Section 2.7): a credential of the subject was found to be
/// compromised - in a data breach, for instance - and the receiver should treat it as burnt.
/// </summary>
public sealed record CredentialCompromisePayload : IEventPayload
{
    /// <summary>
    /// REQUIRED. The type of the compromised credential. RISC 1.0 Section 2.7 defines the value
    /// set by reference to the CAEP Credential Change event, so the values live in
    /// <see cref="CredentialChangePayload.CredentialTypes"/> - one registry for both profiles.
    /// </summary>
    [JsonPropertyName(RiscClaimNames.CredentialType)]
    public required string CredentialType { get; init; }

    /// <summary>
    /// OPTIONAL. When the transmitter DISCOVERED the compromise - not when it happened, which
    /// the transmitter rarely knows (RISC 1.0 Section 2.7). Travels as unix seconds.
    /// </summary>
    [JsonPropertyName(RiscClaimNames.EventTimestamp)]
    [JsonConverter(typeof(DateTimeOffsetUnixTimeSecondsConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? EventTimestamp { get; init; }

    /// <summary>
    /// OPTIONAL. The reason the event was generated, intended for administrators
    /// (RISC 1.0 Section 2.7). The specification leaves the shape unstated; this model reads it
    /// as CAEP 1.0 Section 2 shapes the identically named claim - a map of BCP 47 language tag
    /// to text - since RISC leans on CAEP for its other shared vocabulary.
    /// </summary>
    [JsonPropertyName(RiscClaimNames.ReasonAdmin)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, string>? ReasonAdmin { get; init; }

    /// <summary>
    /// OPTIONAL. The reason the event was generated, intended for end users
    /// (RISC 1.0 Section 2.7), shaped as <see cref="ReasonAdmin"/> is.
    /// </summary>
    [JsonPropertyName(RiscClaimNames.ReasonUser)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, string>? ReasonUser { get; init; }
}
