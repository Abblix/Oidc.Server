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
/// Assurance Level Change (CAEP 1.0 Section 3.4): the subject's authentication strength changed
/// since the initial login, in either direction - a user stepping up with a second factor at
/// one provider is a signal every other provider holding the session may act on. When
/// <see cref="CaepEventPayload.EventTimestamp"/> is included it is the moment of the change.
/// </summary>
public sealed record AssuranceLevelChangePayload : CaepEventPayload
{
    /// <summary>
    /// The level namespaces Section 3.4.1 names. The set is open: any other value is an alias
    /// for a custom namespace the two parties agreed on, which is why
    /// <see cref="Namespace"/> is a string rather than a closed enumeration.
    /// </summary>
    public static class Namespaces
    {
        /// <summary>Values from RFC 8176, Authentication Method Reference Values.</summary>
        public const string Rfc8176 = "RFC8176";

        /// <summary>Values from RFC 6711, the IANA Level of Assurance profiles registry.
        /// </summary>
        public const string Rfc6711 = "RFC6711";

        /// <summary>Values from ISO/IEC 29115.</summary>
        public const string IsoIec29115 = "ISO-IEC-29115";

        /// <summary>NIST Identity Assurance Levels.</summary>
        public const string NistIal = "NIST-IAL";

        /// <summary>NIST Authenticator Assurance Levels.</summary>
        public const string NistAal = "NIST-AAL";

        /// <summary>NIST Federation Assurance Levels.</summary>
        public const string NistFal = "NIST-FAL";
    }

    /// <summary>
    /// The values the "change_direction" member may carry (CAEP 1.0 Section 3.4.1).
    /// </summary>
    public static class ChangeDirections
    {
        /// <summary>The assurance level increased.</summary>
        public const string Increase = "increase";

        /// <summary>The assurance level decreased.</summary>
        public const string Decrease = "decrease";
    }

    /// <summary>
    /// REQUIRED. The namespace the level values come from, one of <see cref="Namespaces"/> or
    /// an agreed custom alias (CAEP 1.0 Section 3.4.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.Namespace)]
    public required string Namespace { get; init; }

    /// <summary>
    /// REQUIRED. The current assurance level, as the namespace defines it
    /// (CAEP 1.0 Section 3.4.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.CurrentLevel)]
    public required string CurrentLevel { get; init; }

    /// <summary>
    /// OPTIONAL. The previous assurance level; absent means the transmitter does not know it
    /// (CAEP 1.0 Section 3.4.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.PreviousLevel)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PreviousLevel { get; init; }

    /// <summary>
    /// OPTIONAL. Which way the level moved, one of <see cref="ChangeDirections"/>; a
    /// transmitter that stated the previous level should state this too
    /// (CAEP 1.0 Section 3.4.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.ChangeDirection)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ChangeDirection { get; init; }
}
