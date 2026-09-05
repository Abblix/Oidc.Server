// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Identifies a subject by an email address (RFC 9493 Section 3.2.2).
/// </summary>
/// <param name="email">
/// The subject's email address, formatted as an "addr-spec" (RFC 5322 Section 3.4.1) and
/// identifying a deliverable mailbox (RFC 5321). REQUIRED, and must be neither null nor empty.
/// </param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[method: JsonConstructor]
public sealed class EmailSubject(string email)
    : SubjectIdentifier(SubjectFormats.Email)
{
    /// <summary>
    /// The email address, as received.
    /// </summary>
    /// <remarks>
    /// Deliberately not canonicalised. RFC 9493 Section 3.2.2.1 records that email
    /// canonicalisation is not standardised and that a receiver cannot know the sending provider's
    /// algorithm, so it puts the choice on the receiver: apply the algorithm your own mail system
    /// uses. Folding case here would silently answer that question on the receiver's behalf and
    /// destroy the original. <see cref="EmailCanonicalization"/> offers the one transformation the
    /// specification does settle, to be applied when comparing rather than when storing.
    /// </remarks>
    [JsonPropertyName(SubjectMemberNames.Email)]
    public string Email { get; } = RequirePresent(email, SubjectMemberNames.Email);
}
