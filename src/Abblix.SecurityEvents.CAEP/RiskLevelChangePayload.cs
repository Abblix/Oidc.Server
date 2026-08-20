// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// Risk Level Change (CAEP 1.0 Section 3.8): the transmitter's assessed risk level for the
/// subject changed at the moment <see cref="CaepEventPayload.EventTimestamp"/> names - a
/// password found in a breach, unapproved software on a device, or any other signal the
/// transmitter abstracts into a level.
/// </summary>
public sealed record RiskLevelChangePayload : CaepEventPayload
{
    /// <summary>
    /// The values both level members carry (CAEP 1.0 Section 3.8.1) - a closed set.
    /// </summary>
    public static class RiskLevels
    {
        /// <summary>Low risk.</summary>
        public const string Low = "LOW";

        /// <summary>Medium risk.</summary>
        public const string Medium = "MEDIUM";

        /// <summary>High risk.</summary>
        public const string High = "HIGH";
    }

    /// <summary>
    /// The principal kinds Section 3.8.1 names, matching the complex-subject member names of
    /// the Shared Signals Framework. The set is open to any other entity the framework's
    /// subject model can express.
    /// </summary>
    public static class Principals
    {
        /// <summary>The risk concerns a user.</summary>
        public const string User = "USER";

        /// <summary>The risk concerns a device.</summary>
        public const string Device = "DEVICE";

        /// <summary>The risk concerns a session.</summary>
        public const string Session = "SESSION";

        /// <summary>The risk concerns a tenant.</summary>
        public const string Tenant = "TENANT";

        /// <summary>The risk concerns an organizational unit.</summary>
        public const string OrgUnit = "ORG_UNIT";

        /// <summary>The risk concerns a group.</summary>
        public const string Group = "GROUP";
    }

    /// <summary>
    /// REQUIRED. The principal entity the observed risk concerns, one of
    /// <see cref="Principals"/> or another entity of the framework's subject model
    /// (CAEP 1.0 Section 3.8.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.Principal)]
    public required string Principal { get; init; }

    /// <summary>
    /// REQUIRED. The current risk level, one of <see cref="RiskLevels"/>
    /// (CAEP 1.0 Section 3.8.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.CurrentLevel)]
    public required string CurrentLevel { get; init; }

    /// <summary>
    /// OPTIONAL. The previously known risk level, one of <see cref="RiskLevels"/>; absent
    /// means the transmitter does not know it (CAEP 1.0 Section 3.8.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.PreviousLevel)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PreviousLevel { get; init; }

    /// <summary>
    /// RECOMMENDED. The reason contributing to the change (CAEP 1.0 Section 3.8.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.RiskReason)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RiskReason { get; init; }
}
