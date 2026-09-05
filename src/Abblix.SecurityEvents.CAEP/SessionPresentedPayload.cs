// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// Session Presented (CAEP 1.0 Section 3.7): the transmitter observed the subject's session to
/// be present at the moment <see cref="CaepEventPayload.EventTimestamp"/> names - the signal
/// receivers build activity anomaly detection and live-session inventories on.
/// </summary>
public sealed record SessionPresentedPayload : CaepEventPayload
{
    /// <summary>
    /// OPTIONAL. The user agent fingerprint the transmitter computed - qualities of the
    /// session, not its identity (CAEP 1.0 Section 3.7.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.FpUa)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FingerprintUserAgent { get; init; }

    /// <summary>
    /// OPTIONAL. The external session identifier correlating this session with a broader one
    /// (CAEP 1.0 Section 3.7.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.ExtId)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ExternalId { get; init; }
}
