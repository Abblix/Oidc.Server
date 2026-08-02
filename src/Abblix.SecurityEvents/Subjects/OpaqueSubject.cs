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
/// Identifies a subject by a string that asserts nothing beyond being its identifier, such as a
/// UUID or a surrogate key for a database record (RFC 9493 Section 3.2.4).
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class OpaqueSubject : SubjectIdentifier
{
    /// <summary>
    /// Creates an Opaque Subject Identifier.
    /// </summary>
    /// <param name="id">
    /// The opaque identifier of the subject. REQUIRED, and must be neither null nor empty.
    /// </param>
    [JsonConstructor]
    public OpaqueSubject(string id)
        : base(SubjectFormats.Opaque)
    {
        Id = RequirePresent(id, SubjectMemberNames.Id);
    }

    /// <summary>
    /// The opaque identifier. It carries no semantics, so it is compared as an exact string and
    /// never interpreted, normalised or parsed.
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Id)]
    public string Id { get; }
}
