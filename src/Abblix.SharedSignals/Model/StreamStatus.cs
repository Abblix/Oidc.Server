// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
