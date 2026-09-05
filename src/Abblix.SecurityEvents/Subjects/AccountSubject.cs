// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Identifies a subject by an account at a service provider, expressed as an "acct" URI
/// (RFC 9493 Section 3.2.1, RFC 7565).
/// </summary>
/// <param name="uri">
/// The "acct" URI of the subject's account. REQUIRED, and must be neither null nor empty.
/// </param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[method: JsonConstructor]
public sealed class AccountSubject(string uri)
    : SubjectIdentifier(SubjectFormats.Account)
{
    /// <summary>
    /// The "acct" URI identifying the account (RFC 7565).
    /// </summary>
    /// <remarks>
    /// The value is carried as written, and that leniency is the decision taken: RFC 9493
    /// Section 3.2.1 requires the value to be the subject's "acct" URI, but this type does not
    /// verify the scheme, for the same reason <see cref="EmailSubject"/> does not parse addr-spec
    /// and <see cref="PhoneNumberSubject"/> does not enforce E.164 - a receiver that discarded an
    /// event over a malformed value would lose a signal it could still act on, so lexical
    /// validation is left to the application that chooses to refuse. No canonicalisation is stated
    /// by the RFC either, so two spellings of one account remain two distinct identifiers here.
    /// </remarks>
    [JsonPropertyName(SubjectMemberNames.Uri)]
    public string Uri { get; } = RequirePresent(uri, SubjectMemberNames.Uri);
}
