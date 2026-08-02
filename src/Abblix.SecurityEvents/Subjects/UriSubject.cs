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
/// Identifies a subject by a URI (RFC 9493 Section 3.2.7, RFC 3986).
/// </summary>
/// <remarks>
/// This is the least specific of the formats, and RFC 9493 Section 3.2 asks applications to choose
/// the most specific one available: an email address belongs in <see cref="EmailSubject"/> rather
/// than in a "mailto:" URI here, because the format itself conveys meaning to the receiver.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class UriSubject : SubjectIdentifier
{
    /// <summary>
    /// Creates a URI Subject Identifier.
    /// </summary>
    /// <param name="uri">
    /// A URI for the subject. REQUIRED, and must be neither null nor empty.
    /// </param>
    [JsonConstructor]
    public UriSubject(string uri)
        : base(SubjectFormats.Uri)
    {
        Uri = RequirePresent(uri, SubjectMemberNames.Uri);
    }

    /// <summary>
    /// The URI identifying the subject. RFC 9493 Section 3.2.7 makes no promise about its content,
    /// scheme or reachability, so it is neither dereferenced nor required to name a live resource.
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Uri)]
    public string Uri { get; }
}
