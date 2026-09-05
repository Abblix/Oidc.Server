// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Identifies a subject that is itself a JWT, by the issuer that minted it and its token
/// identifier (SSF 1.0 Section 3.5.1) - the shape a CAEP token-revocation event names its
/// victim in.
/// </summary>
/// <param name="issuer">
/// The "iss" claim of the JWT being identified (RFC 7519). REQUIRED, and must be neither null
/// nor empty.</param>
/// <param name="jwtId">
/// The "jti" claim of the JWT being identified (RFC 7519). REQUIRED, and must be neither null
/// nor empty.</param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
[method: JsonConstructor]
public sealed class JwtIdSubject(string issuer, string jwtId)
    : SubjectIdentifier(SubjectFormats.JwtId)
{
    /// <summary>
    /// The "iss" claim of the JWT being identified (SSF 1.0 Section 3.5.1).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Issuer)]
    public string Issuer { get; } = RequirePresent(issuer, SubjectMemberNames.Issuer);

    /// <summary>
    /// The "jti" claim of the JWT being identified (SSF 1.0 Section 3.5.1).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.JwtId)]
    public string JwtId { get; } = RequirePresent(jwtId, SubjectMemberNames.JwtId);
}
