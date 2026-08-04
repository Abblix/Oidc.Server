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
/// Identifies a subject that is a SAML 2.0 assertion, by the assertion's Issuer and ID values
/// (SSF 1.0 Section 3.5.2). Note the member names differ from the jwt_id format's: the full
/// words "issuer" and "assertion_id", not the JWT claim abbreviations.
/// </summary>
/// <param name="issuer">
/// The Issuer value of the SAML assertion being identified. REQUIRED, and must be neither null
/// nor empty.</param>
/// <param name="assertionId">
/// The ID value of the SAML assertion being identified. REQUIRED, and must be neither null nor
/// empty.</param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[method: JsonConstructor]
public sealed class SamlAssertionIdSubject(string issuer, string assertionId)
    : SubjectIdentifier(SubjectFormats.SamlAssertionId)
{
    /// <summary>
    /// The Issuer value of the SAML assertion being identified (SSF 1.0 Section 3.5.2).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.SamlIssuer)]
    public string Issuer { get; } = RequirePresent(issuer, SubjectMemberNames.SamlIssuer);

    /// <summary>
    /// The ID value of the SAML assertion being identified (SSF 1.0 Section 3.5.2).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.AssertionId)]
    public string AssertionId { get; } = RequirePresent(assertionId, SubjectMemberNames.AssertionId);
}
