// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
