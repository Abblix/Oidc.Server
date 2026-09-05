// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
