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
