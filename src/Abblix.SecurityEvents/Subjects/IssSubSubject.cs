// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Identifies a subject by a pair of issuer and subject values, the way an OpenID Connect ID token
/// identifies its subject through the "iss" and "sub" claims (RFC 9493 Section 3.2.3).
/// </summary>
/// <remarks>
/// When this identifier sits in a JWT's "sub_id" claim, its <see cref="Issuer"/> and
/// <see cref="Subject"/> members MAY differ from the JWT's own "iss" and "sub" claims
/// (RFC 9493 Section 4.2): that is how a party names a subject by an identity its counterparty
/// already understands rather than by its own local one.
/// </remarks>
/// <param name="issuer">
/// The identity issuer, following the format of the JWT "iss" claim (RFC 7519).
/// REQUIRED, and must be neither null nor empty.</param>
/// <param name="subject">
/// The subject at that issuer, following the format of the JWT "sub" claim (RFC 7519).
/// REQUIRED, and must be neither null nor empty.</param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[method: JsonConstructor]
public sealed class IssSubSubject(string issuer, string subject)
    : SubjectIdentifier(SubjectFormats.IssSub)
{
    /// <summary>
    /// The issuer of the identity, in the format of the JWT "iss" claim (RFC 7519 Section 4.1.1).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Issuer)]
    public string Issuer { get; } = RequirePresent(issuer, SubjectMemberNames.Issuer);

    /// <summary>
    /// The subject at that issuer, in the format of the JWT "sub" claim (RFC 7519 Section 4.1.2).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Subject)]
    public string Subject { get; } = RequirePresent(subject, SubjectMemberNames.Subject);
}
