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
public sealed class AccountSubject(Uri uri)
    : SubjectIdentifier(SubjectFormats.Account)
{
    /// <summary>
    /// The "acct" URI identifying the account (RFC 7565).
    /// </summary>
    /// <remarks>
    /// RFC 9493 Section 3.2.1 requires the value to be the subject's "acct" URI, so a value that is not an
    /// absolute URI is refused; the scheme itself is not checked, which leaves the account's own spelling to the
    /// application. No canonicalization is stated by the RFC, so the value keeps the spelling it was written
    /// with, and two spellings of one account remain two distinct identifiers.
    /// </remarks>
    [JsonPropertyName(SubjectMemberNames.Uri)]
    public Uri Uri { get; } = RequireUri(uri, SubjectMemberNames.Uri);
}
