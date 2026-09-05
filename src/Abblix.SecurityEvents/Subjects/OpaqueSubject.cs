// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Identifies a subject by a string that asserts nothing beyond being its identifier, such as a
/// UUID or a surrogate key for a database record (RFC 9493 Section 3.2.4).
/// </summary>
/// <param name="id">
/// The opaque identifier of the subject. REQUIRED, and must be neither null nor empty.
/// </param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[method: JsonConstructor]
public sealed class OpaqueSubject(string id)
    : SubjectIdentifier(SubjectFormats.Opaque)
{
    /// <summary>
    /// The opaque identifier. It carries no semantics, so it is compared as an exact string and
    /// never interpreted, normalised or parsed.
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Id)]
    public string Id { get; } = RequirePresent(id, SubjectMemberNames.Id);
}
