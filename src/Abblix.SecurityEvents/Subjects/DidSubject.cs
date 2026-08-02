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

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Identifies a subject by a Decentralized Identifier URL (RFC 9493 Section 3.2.6).
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class DidSubject : SubjectIdentifier
{
    /// <summary>
    /// Creates a Decentralized Identifier Subject Identifier.
    /// </summary>
    /// <param name="url">
    /// A DID URL for the subject. RFC 9493 Section 3.2.6 permits a bare DID as well as a DID URL
    /// carrying path, query or fragment components. REQUIRED, and must be neither null nor empty.
    /// </param>
    [JsonConstructor]
    public DidSubject(string url)
        : base(SubjectFormats.Did)
    {
        Url = RequirePresent(url, SubjectMemberNames.Url);
    }

    /// <summary>
    /// The DID URL identifying the subject.
    /// </summary>
    /// <remarks>
    /// Held as a string rather than a parsed URL. DID syntax is governed by the DID specification,
    /// whose method-specific identifiers the .NET URI parser does not know; parsing here would
    /// reject valid DIDs from methods this library has never heard of.
    /// </remarks>
    [JsonPropertyName(SubjectMemberNames.Url)]
    public string Url { get; }
}
