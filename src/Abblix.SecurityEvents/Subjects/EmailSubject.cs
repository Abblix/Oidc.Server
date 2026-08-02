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
