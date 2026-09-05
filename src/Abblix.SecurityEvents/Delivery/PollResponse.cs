// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
