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

namespace Abblix.SecurityEvents.Delivery;

/// <summary>
/// The body a SET Transmitter returns to a poll (RFC 8936 Section 2.3): the SETs being delivered,
/// keyed by "jti" with each value the compact serialization, and whether more wait behind them.
/// </summary>
public record PollResponse
{
    /// <summary>
    /// The SETs being delivered - first deliveries and unacknowledged redeliveries alike - keyed
    /// by "jti". "If there are no outstanding SETs to be transmitted, the JSON object SHALL be
    /// empty" (RFC 8936 Section 2.3), which is why the member is never absent and defaults to the
    /// empty map rather than null.
    /// </summary>
    [JsonPropertyName(ParameterNames.Sets)]
    public IReadOnlyDictionary<string, string> Sets { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// Whether more unacknowledged SETs wait beyond this response. Omitted means false
    /// (RFC 8936 Section 2.3), so the property is nullable and an absent member stays absent on
    /// re-serialization.
    /// </summary>
    [JsonPropertyName(ParameterNames.MoreAvailable)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? MoreAvailable { get; init; }

    /// <summary>
    /// The wire names of the poll response members (RFC 8936 Section 2.3).
    /// </summary>
    public static class ParameterNames
    {
        /// <summary>
        /// The delivered-tokens member.
        /// </summary>
        public const string Sets = "sets";

        /// <summary>
        /// The more-waiting indicator member.
        /// </summary>
        public const string MoreAvailable = "moreAvailable";
    }
}
