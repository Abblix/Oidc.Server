// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Identifies a subject by a Decentralized Identifier URL (RFC 9493 Section 3.2.6).
/// </summary>
/// <param name="url">
/// A DID URL for the subject. RFC 9493 Section 3.2.6 permits a bare DID as well as a DID URL
/// carrying path, query or fragment components. REQUIRED, and must be neither null nor empty.
/// </param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[method: JsonConstructor]
public sealed class DidSubject(Uri url)
    : SubjectIdentifier(SubjectFormats.Did)
{
    /// <summary>
    /// The DID URL identifying the subject.
    /// </summary>
    /// <remarks>
    /// RFC 9493 Section 3.2.6 requires a valid DID URL, and a DID URL is an absolute URI of the <c>did</c>
    /// scheme whatever its method, so a value that is not an absolute URI is refused.
    /// </remarks>
    [JsonPropertyName(SubjectMemberNames.Url)]
    public Uri Url { get; } = RequireUri(url, SubjectMemberNames.Url);
}
