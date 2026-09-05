// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
/// <param name="uri">
/// A URI for the subject. REQUIRED, and must be neither null nor empty.
/// </param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[method: JsonConstructor]
public sealed class UriSubject(string uri)
    : SubjectIdentifier(SubjectFormats.Uri)
{
    /// <summary>
    /// The URI identifying the subject. RFC 9493 Section 3.2.7 makes no promise about its content,
    /// scheme or reachability, so it is neither dereferenced nor required to name a live resource.
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Uri)]
    public string Uri { get; } = RequirePresent(uri, SubjectMemberNames.Uri);
}
