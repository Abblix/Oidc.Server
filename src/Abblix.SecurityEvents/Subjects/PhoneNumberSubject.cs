// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Identifies a subject by a telephone number (RFC 9493 Section 3.2.5).
/// </summary>
/// <param name="phoneNumber">
/// The subject's full telephone number including its international dialling prefix, formatted
/// according to E.164. REQUIRED, and must be neither null nor empty.</param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[method: JsonConstructor]
public sealed class PhoneNumberSubject(string phoneNumber)
    : SubjectIdentifier(SubjectFormats.PhoneNumber)
{
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
    public string PhoneNumber { get; } = RequirePresent(phoneNumber, SubjectMemberNames.PhoneNumber);
}
