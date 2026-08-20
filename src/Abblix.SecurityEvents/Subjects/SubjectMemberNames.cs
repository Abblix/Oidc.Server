// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Names of the JSON members a Subject Identifier may carry. A member name is shared with whoever
/// reads the identifier on the other side, so it is single-sourced here rather than repeated as a
/// literal at each declaration. Each constant names its origin: the RFC 9493 formats
/// (Section 3.2) or the OpenID Shared Signals Framework 1.0 extensions (Sections 3.3, 3.5).
/// </summary>
public static class SubjectMemberNames
{
    /// <summary>
    /// The Identifier Format name. REQUIRED on every Subject Identifier and reserved by
    /// RFC 9493 Section 3, which forbids an Identifier Format from declaring rules about it.
    /// </summary>
    public const string Format = "format";

    /// <summary>
    /// The "acct" URI of the Account Identifier Format, and the URI of the URI Identifier Format
    /// (RFC 9493 Sections 3.2.1 and 3.2.7). One name serving two formats is what the specification
    /// defines; the formats are told apart by <see cref="Format"/>, never by their members.
    /// </summary>
    public const string Uri = "uri";

    /// <summary>
    /// The email address of the Email Identifier Format (RFC 9493 Section 3.2.2).
    /// </summary>
    public const string Email = "email";

    /// <summary>
    /// The issuer half of the Issuer and Subject Identifier Format (RFC 9493 Section 3.2.3).
    /// </summary>
    public const string Issuer = "iss";

    /// <summary>
    /// The subject half of the Issuer and Subject Identifier Format (RFC 9493 Section 3.2.3).
    /// </summary>
    public const string Subject = "sub";

    /// <summary>
    /// The identifier string of the Opaque Identifier Format (RFC 9493 Section 3.2.4).
    /// </summary>
    public const string Id = "id";

    /// <summary>
    /// The telephone number of the Phone Number Identifier Format (RFC 9493 Section 3.2.5).
    /// </summary>
    public const string PhoneNumber = "phone_number";

    /// <summary>
    /// The DID URL of the Decentralized Identifier Format (RFC 9493 Section 3.2.6).
    /// </summary>
    public const string Url = "url";

    /// <summary>
    /// The array of nested Subject Identifiers of the Aliases Identifier Format
    /// (RFC 9493 Section 3.2.8).
    /// </summary>
    public const string Identifiers = "identifiers";

    /// <summary>
    /// The "jti" claim of the JWT the SSF JWT ID Identifier Format names
    /// (SSF 1.0 Section 3.5.1).
    /// </summary>
    public const string JwtId = "jti";

    /// <summary>
    /// The Issuer value of the SSF SAML Assertion ID Identifier Format (SSF 1.0 Section 3.5.2) -
    /// the full word, unlike the "iss" the JWT-derived formats use.
    /// </summary>
    public const string SamlIssuer = "issuer";

    /// <summary>
    /// The ID value of the SSF SAML Assertion ID Identifier Format (SSF 1.0 Section 3.5.2).
    /// </summary>
    public const string AssertionId = "assertion_id";

    /// <summary>
    /// The address array of the SSF IP Addresses Identifier Format (SSF 1.0 Section 3.5.3).
    /// </summary>
    public const string IpAddresses = "ip-addresses";

    /// <summary>
    /// A user, within an SSF Complex Subject (SSF 1.0 Section 3.3).
    /// </summary>
    public const string User = "user";

    /// <summary>
    /// A device, within an SSF Complex Subject (SSF 1.0 Section 3.3).
    /// </summary>
    public const string Device = "device";

    /// <summary>
    /// A session, within an SSF Complex Subject (SSF 1.0 Section 3.3).
    /// </summary>
    public const string Session = "session";

    /// <summary>
    /// An application, within an SSF Complex Subject (SSF 1.0 Section 3.3).
    /// </summary>
    public const string Application = "application";

    /// <summary>
    /// A tenant, within an SSF Complex Subject (SSF 1.0 Section 3.3).
    /// </summary>
    public const string Tenant = "tenant";

    /// <summary>
    /// An organizational unit, within an SSF Complex Subject (SSF 1.0 Section 3.3).
    /// </summary>
    public const string OrgUnit = "org_unit";

    /// <summary>
    /// A group, within an SSF Complex Subject (SSF 1.0 Section 3.3).
    /// </summary>
    public const string Group = "group";
}
