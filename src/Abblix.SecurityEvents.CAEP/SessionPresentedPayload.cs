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

namespace Abblix.SecurityEvents.Caep;

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
