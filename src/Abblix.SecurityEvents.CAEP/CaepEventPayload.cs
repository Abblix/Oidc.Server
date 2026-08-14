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
using Abblix.Utils.Json;

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// The claims every CAEP event may carry (CAEP 1.0 Section 2): when it happened, who set it in
/// motion, and why - the latter twice, because the administrator's log line and the sentence an
/// end user should read are different texts in different languages.
/// </summary>
public abstract record CaepEventPayload : IEventPayload
{
    /// <summary>
    /// The values the "initiating_entity" claim may carry (CAEP 1.0 Section 2).
    /// </summary>
    public static class InitiatingEntities
    {
        /// <summary>An administrative action triggered the event.</summary>
        public const string Admin = "admin";

        /// <summary>An end-user action triggered the event.</summary>
        public const string User = "user";

        /// <summary>A policy evaluation triggered the event.</summary>
        public const string Policy = "policy";

        /// <summary>A system or platform assertion triggered the event.</summary>
        public const string System = "system";
    }

    /// <summary>
    /// OPTIONAL. When the event described by the SET occurred - each event type binds this to
    /// its own moment, such as when the session was revoked or the credential changed
    /// (CAEP 1.0 Sections 2, 3). Travels as unix seconds.
    /// </summary>
    [JsonPropertyName(CaepClaimNames.EventTimestamp)]
    [JsonConverter(typeof(DateTimeOffsetUnixTimeSecondsConverter))]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? EventTimestamp { get; init; }

    /// <summary>
    /// OPTIONAL. The entity that invoked the event, one of
    /// <see cref="InitiatingEntities"/> (CAEP 1.0 Section 2).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.InitiatingEntity)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? InitiatingEntity { get; init; }

    /// <summary>
    /// OPTIONAL. The administrative message for logging and auditing, keyed by BCP 47 language
    /// tag (CAEP 1.0 Section 2).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.ReasonAdmin)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, string>? ReasonAdmin { get; init; }

    /// <summary>
    /// OPTIONAL. The message for display to an end user, keyed by BCP 47 language tag
    /// (CAEP 1.0 Section 2).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.ReasonUser)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, string>? ReasonUser { get; init; }
}
