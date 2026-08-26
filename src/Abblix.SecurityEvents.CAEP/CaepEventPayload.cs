// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
    /// <remarks>
    /// Optional to CAEP 1.0, and required of a TRANSMITTER by the CAEP Interoperability Profile 1.0: each
    /// of the three use cases in its Section 3 demands a non-empty object here. The property stays
    /// nullable because the two documents disagree and the receive side follows the base specification -
    /// CAEP 1.0 Section 3.1.1 positively requires an empty <c>session-revoked</c> payload to be accepted.
    /// A deployment claiming the profile registers <see cref="CaepInteropProfilePolicy"/>, which refuses
    /// the event rather than the type.
    /// </remarks>
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
