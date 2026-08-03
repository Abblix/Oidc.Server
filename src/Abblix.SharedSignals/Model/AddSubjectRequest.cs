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
/// The body of a receiver's request to add a subject to an Event Stream
/// (SSF 1.0 Section 8.1.3.2). Success is an empty 200 - and deliberately proves nothing: a
/// transmitter may silently ignore the addition, for example when the subject opted out of
/// having events sent to this receiver, precisely so the response cannot be used to probe who
/// is known to the transmitter (SSF 1.0 Sections 8.1.3.2, 9.1).
/// </summary>
public sealed record AddSubjectRequest
{
    /// <summary>
    /// REQUIRED. The stream the subject is being added to (SSF 1.0 Section 8.1.3.2).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.StreamId)]
    public required string StreamId { get; init; }

    /// <summary>
    /// REQUIRED. The subject being added, in any RFC 9493 Identifier Format the transmitter
    /// understands (SSF 1.0 Section 8.1.3.2).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Subject)]
    public required SubjectIdentifier Subject { get; init; }

    /// <summary>
    /// OPTIONAL. Whether the receiver has verified the subject claim; when omitted the
    /// transmitter should assume it has been (SSF 1.0 Section 8.1.3.2), so only an explicit
    /// "not verified" is worth sending.
    /// </summary>
    [JsonPropertyName(StreamMemberNames.Verified)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Verified { get; init; }
}
