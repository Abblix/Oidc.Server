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

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// Device Compliance Change (CAEP 1.0 Section 3.5): the compliance status of the device
/// identified by the subject changed. When <see cref="CaepEventPayload.EventTimestamp"/> is
/// included it is the moment of the change.
/// </summary>
public sealed record DeviceComplianceChangePayload : CaepEventPayload
{
    /// <summary>
    /// The values both status members carry (CAEP 1.0 Section 3.5.1).
    /// </summary>
    public static class ComplianceStatuses
    {
        /// <summary>The device complies with policy.</summary>
        public const string Compliant = "compliant";

        /// <summary>The device does not comply with policy.</summary>
        public const string NotCompliant = "not-compliant";
    }

    /// <summary>
    /// REQUIRED. The status before the change, one of <see cref="ComplianceStatuses"/>
    /// (CAEP 1.0 Section 3.5.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.PreviousStatus)]
    public required string PreviousStatus { get; init; }

    /// <summary>
    /// REQUIRED. The status that triggered the event, one of <see cref="ComplianceStatuses"/>
    /// (CAEP 1.0 Section 3.5.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.CurrentStatus)]
    public required string CurrentStatus { get; init; }
}
