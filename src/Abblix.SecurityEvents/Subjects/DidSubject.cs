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
public sealed class DidSubject(string url)
    : SubjectIdentifier(SubjectFormats.Did)
{
    /// <summary>
    /// The DID URL identifying the subject.
    /// </summary>
    /// <remarks>
    /// Held as a string rather than a parsed URL. DID syntax is governed by the DID specification,
    /// whose method-specific identifiers the .NET URI parser does not know; parsing here would
    /// reject valid DIDs from methods this library has never heard of.
    /// </remarks>
    [JsonPropertyName(SubjectMemberNames.Url)]
    public string Url { get; } = RequirePresent(url, SubjectMemberNames.Url);
}
