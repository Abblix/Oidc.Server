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
