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
/// Identifies a subject by a pair of issuer and subject values, the way an OpenID Connect ID token
/// identifies its subject through the "iss" and "sub" claims (RFC 9493 Section 3.2.3).
/// </summary>
/// <remarks>
/// When this identifier sits in a JWT's "sub_id" claim, its <see cref="Issuer"/> and
/// <see cref="Subject"/> members MAY differ from the JWT's own "iss" and "sub" claims
/// (RFC 9493 Section 4.2): that is how a party names a subject by an identity its counterparty
/// already understands rather than by its own local one.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class IssSubSubject : SubjectIdentifier
{
    /// <summary>
    /// Creates an Issuer and Subject Identifier.
    /// </summary>
    /// <param name="issuer">
    /// The identity issuer, following the format of the JWT "iss" claim (RFC 7519).
    /// REQUIRED, and must be neither null nor empty.</param>
    /// <param name="subject">
    /// The subject at that issuer, following the format of the JWT "sub" claim (RFC 7519).
    /// REQUIRED, and must be neither null nor empty.</param>
    [JsonConstructor]
    public IssSubSubject(string issuer, string subject)
        : base(SubjectFormats.IssSub)
    {
        Issuer = RequirePresent(issuer, SubjectMemberNames.Issuer);
        Subject = RequirePresent(subject, SubjectMemberNames.Subject);
    }

    /// <summary>
    /// The issuer of the identity, in the format of the JWT "iss" claim (RFC 7519 Section 4.1.1).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Issuer)]
    public string Issuer { get; }

    /// <summary>
    /// The subject at that issuer, in the format of the JWT "sub" claim (RFC 7519 Section 4.1.2).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Subject)]
    public string Subject { get; }
}
