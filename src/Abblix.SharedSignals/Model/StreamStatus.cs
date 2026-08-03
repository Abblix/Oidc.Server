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

namespace Abblix.SharedSignals.Model;

/// <summary>
/// An Event Stream's status document: one shape for both directions, because the read response
/// (SSF 1.0 Section 8.1.2.1) and the update request and its echo (Section 8.1.2.2) carry the
/// same three members.
/// </summary>
public sealed record StreamStatus
{
    /// <summary>
    /// REQUIRED. The stream whose status this is (SSF 1.0 Section 8.1.2).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.StreamId)]
    public required string StreamId { get; init; }

    /// <summary>
    /// REQUIRED. The status value, one of <see cref="StreamStatuses"/>
    /// (SSF 1.0 Section 8.1.2.1).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Status)]
    public required string Status { get; init; }

    /// <summary>
    /// OPTIONAL. Why the status is what it is (SSF 1.0 Section 8.1.2).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Reason)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Reason { get; init; }
}
