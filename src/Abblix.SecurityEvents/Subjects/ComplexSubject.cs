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

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// A Complex Subject: several Simple Subject Members - a user, the device they are on, the
/// session they hold - that all describe attributes of, and together refer to, exactly one
/// Subject Principal (SSF 1.0 Sections 3.3, 3.3.1).
/// </summary>
/// <remarks>
/// <para>
/// Section 3.3 requires at least one member, a rule spanning all of them at once; it belongs to
/// a validation pass over the whole document, not to any single property, and is not enforced
/// here. What IS enforced per member is simplicity: a Complex Subject holds Simple Subject
/// Members, so a nested Complex Subject is refused on the way in - built in code or read off
/// the wire alike.
/// </para>
/// <para>
/// Section 3.3 also allows additional member names beyond the registered seven. They land in
/// <see cref="AdditionalMembers"/> as raw JSON and are written back verbatim, which is exactly
/// the posture Section 3.6 asks of a receiver: members it cannot interpret stay visible - so
/// the check for an unprocessable Critical member can see them - rather than being dropped or
/// refused.
/// </para>
/// </remarks>
public sealed class ComplexSubject() : SubjectIdentifier(SubjectFormats.Complex)
{
    private readonly SubjectIdentifier? _user;
    private readonly SubjectIdentifier? _device;
    private readonly SubjectIdentifier? _session;
    private readonly SubjectIdentifier? _application;
    private readonly SubjectIdentifier? _tenant;
    private readonly SubjectIdentifier? _orgUnit;
    private readonly SubjectIdentifier? _group;

    /// <summary>
    /// OPTIONAL. Identifies a user (SSF 1.0 Section 3.3).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.User)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SubjectIdentifier? User
    {
        get => _user;
        init => _user = RequireSimple(value, SubjectMemberNames.User);
    }

    /// <summary>
    /// OPTIONAL. Identifies a device (SSF 1.0 Section 3.3).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Device)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SubjectIdentifier? Device
    {
        get => _device;
        init => _device = RequireSimple(value, SubjectMemberNames.Device);
    }

    /// <summary>
    /// OPTIONAL. Identifies a session (SSF 1.0 Section 3.3).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Session)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SubjectIdentifier? Session
    {
        get => _session;
        init => _session = RequireSimple(value, SubjectMemberNames.Session);
    }

    /// <summary>
    /// OPTIONAL. Identifies an application (SSF 1.0 Section 3.3).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Application)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SubjectIdentifier? Application
    {
        get => _application;
        init => _application = RequireSimple(value, SubjectMemberNames.Application);
    }

    /// <summary>
    /// OPTIONAL. Identifies a tenant (SSF 1.0 Section 3.3).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Tenant)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SubjectIdentifier? Tenant
    {
        get => _tenant;
        init => _tenant = RequireSimple(value, SubjectMemberNames.Tenant);
    }

    /// <summary>
    /// OPTIONAL. Identifies an organizational unit (SSF 1.0 Section 3.3).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.OrgUnit)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SubjectIdentifier? OrgUnit
    {
        get => _orgUnit;
        init => _orgUnit = RequireSimple(value, SubjectMemberNames.OrgUnit);
    }

    /// <summary>
    /// OPTIONAL. Identifies a group (SSF 1.0 Section 3.3).
    /// </summary>
    [JsonPropertyName(SubjectMemberNames.Group)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SubjectIdentifier? Group
    {
        get => _group;
        init => _group = RequireSimple(value, SubjectMemberNames.Group);
    }

    /// <summary>
    /// The members beyond the registered seven that SSF 1.0 Section 3.3 permits, kept as raw
    /// JSON: this package cannot interpret them, and preserving them verbatim is what lets a
    /// receiver's critical-member check (Section 3.6) and a re-transmission see them intact.
    /// </summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalMembers { get; init; }

    /// <summary>
    /// Returns <paramref name="value"/> unless it is itself a Complex Subject: the members of a
    /// Complex Subject are Simple Subject Members (SSF 1.0 Section 3.3), so nesting is refused
    /// at construction - which makes the rule bind a wire document in the same line it binds
    /// code, via the constructor-translating dispatch of the subject converter.
    /// </summary>
    /// <param name="value">The member value being set.</param>
    /// <param name="memberName">The member's wire name, for the refusal message.</param>
    private static SubjectIdentifier? RequireSimple(SubjectIdentifier? value, string memberName)
        => value is not ComplexSubject
            ? value
            : throw new ArgumentException(
                $"The '{memberName}' member of a Complex Subject must be a Simple Subject Member; "
                + $"a nested '{SubjectFormats.Complex}' subject is not one (SSF 1.0 Section 3.3).",
                memberName);
}
