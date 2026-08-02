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
/// The body a SET Recipient posts to a transmitter's polling endpoint (RFC 8936 Section 2.2):
/// what to return now, and what of the previous delivery is being acknowledged. The three request
/// variations of Section 2.4 - poll-only, acknowledge-only, combined - are all spellings of this
/// one object.
/// </summary>
/// <remarks>
/// Every member is optional and an absent member is omitted from the wire, not sent as null: the
/// empty JSON object is the specification's own example of a valid default poll. Absence has
/// meaning here - an omitted <see cref="MaxEvents"/> is "no limit", where a zero is
/// "acknowledge only" - so the properties are nullable rather than defaulted.
/// </remarks>
public record PollRequest
{
    /// <summary>
    /// The most unacknowledged SETs the transmitter should return. Zero makes the request
    /// acknowledge-only; absent places no limit (RFC 8936 Section 2.2).
    /// </summary>
    [JsonPropertyName(ParameterNames.MaxEvents)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MaxEvents { get; init; }

    /// <summary>
    /// True asks for an immediate response even when no SETs are available - short polling.
    /// Absent or false makes the request a long poll (RFC 8936 Section 2.2).
    /// </summary>
    [JsonPropertyName(ParameterNames.ReturnImmediately)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? ReturnImmediately { get; init; }

    /// <summary>
    /// The "jti" values of SETs received successfully, whose acknowledgement releases the
    /// transmitter from retaining them (RFC 8936 Section 2.2).
    /// </summary>
    [JsonPropertyName(ParameterNames.Acknowledged)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Acknowledged { get; init; }

    /// <summary>
    /// The invalid SETs of the previous delivery, keyed by "jti", each with the error that
    /// condemned it (RFC 8936 Section 2.2).
    /// </summary>
    [JsonPropertyName(ParameterNames.Errors)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, DeliveryError>? Errors { get; init; }

    /// <summary>
    /// The wire names of the poll request members (RFC 8936 Section 2.2).
    /// </summary>
    public static class ParameterNames
    {
        /// <summary>
        /// The maximum-events member.
        /// </summary>
        public const string MaxEvents = "maxEvents";

        /// <summary>
        /// The short-poll switch member.
        /// </summary>
        public const string ReturnImmediately = "returnImmediately";

        /// <summary>
        /// The acknowledgement member.
        /// </summary>
        public const string Acknowledged = "ack";

        /// <summary>
        /// The per-token error report member.
        /// </summary>
        public const string Errors = "setErrs";
    }
}
