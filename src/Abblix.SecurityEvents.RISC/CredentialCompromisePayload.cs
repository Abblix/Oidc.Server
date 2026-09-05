// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;
using Abblix.SecurityEvents.CAEP;
using Abblix.SecurityEvents.Events;
using Abblix.Utils.Json;

namespace Abblix.SecurityEvents.RISC;

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
