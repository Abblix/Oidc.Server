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
/// Identifies a subject by an account at a service provider, expressed as an "acct" URI
/// (RFC 9493 Section 3.2.1, RFC 7565).
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AccountSubject : SubjectIdentifier
{
    /// <summary>
    /// Creates an Account Subject Identifier.
    /// </summary>
    /// <param name="uri">
    /// The "acct" URI of the subject's account. REQUIRED, and must be neither null nor empty.
    /// </param>
    [JsonConstructor]
    public AccountSubject(string uri)
        : base(SubjectFormats.Account)
    {
        Uri = RequirePresent(uri, SubjectMemberNames.Uri);
    }

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
    public string Uri { get; }
}
