// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;
using Abblix.SecurityEvents.Subjects;

namespace Abblix.SharedSignals.Model;

/// <summary>
/// The body of a receiver's request to remove a subject from an Event Stream
/// (SSF 1.0 Section 8.1.3.3). Success is an empty 204; as with adding, a transmitter may answer
/// success without acting, so the response reveals nothing about who it knows
/// (SSF 1.0 Sections 8.1.3.3, 9.1).
/// </summary>
public sealed record RemoveSubjectRequest
{
    /// <summary>
    /// REQUIRED. The stream the subject is being removed from (SSF 1.0 Section 8.1.3.3).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.StreamId)]
    public required string StreamId { get; init; }

    /// <summary>
    /// REQUIRED. The subject being removed (SSF 1.0 Section 8.1.3.3).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Subject)]
    public required SubjectIdentifier Subject { get; init; }
}
