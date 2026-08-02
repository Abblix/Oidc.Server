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
/// Identifies a subject by a telephone number (RFC 9493 Section 3.2.5).
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class PhoneNumberSubject : SubjectIdentifier
{
    /// <summary>
    /// Creates a Phone Number Subject Identifier.
    /// </summary>
    /// <param name="phoneNumber">
    /// The subject's full telephone number including its international dialling prefix, formatted
    /// according to E.164. REQUIRED, and must be neither null nor empty.</param>
    [JsonConstructor]
    public PhoneNumberSubject(string phoneNumber)
        : base(SubjectFormats.PhoneNumber)
    {
        PhoneNumber = RequirePresent(phoneNumber, SubjectMemberNames.PhoneNumber);
    }

    /// <summary>
    /// The telephone number, as received.
    /// </summary>
    /// <remarks>
    /// E.164 form is what RFC 9493 Section 3.2.5 requires of the sender, so this library neither
    /// reformats an incoming value nor rejects one that departs from E.164: a receiver that
    /// discarded such an event would lose a signal it could still act on, and a receiver that
    /// rewrote it would be guessing at the sender's intent. Compare through
    /// <see cref="PhoneNumberCanonicalization"/> when values from different senders must meet.
    /// </remarks>
    [JsonPropertyName(SubjectMemberNames.PhoneNumber)]
    public string PhoneNumber { get; }
}
