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

namespace Abblix.SharedSignals.Subjects;

/// <summary>
/// The wire names of the members appearing in the Subject Identifiers SSF 1.0 adds
/// (Sections 3.3, 3.5). Members shared with RFC 9493 formats keep their constants in the
/// SecurityEvents registry; only the names SSF introduces live here.
/// </summary>
public static class SsfSubjectMemberNames
{
    /// <summary>The "jti" claim of the JWT being identified (SSF 1.0 Section 3.5.1).</summary>
    public const string JwtId = "jti";

    /// <summary>
    /// The Issuer value of the SAML assertion being identified (SSF 1.0 Section 3.5.2) - the
    /// full word, unlike the "iss" of the jwt_id format.
    /// </summary>
    public const string Issuer = "issuer";

    /// <summary>The ID value of the SAML assertion being identified (SSF 1.0 Section 3.5.2).
    /// </summary>
    public const string AssertionId = "assertion_id";

    /// <summary>The array of observed IP addresses (SSF 1.0 Section 3.5.3).</summary>
    public const string IpAddresses = "ip-addresses";

    /// <summary>A user, within a Complex Subject (SSF 1.0 Section 3.3).</summary>
    public const string User = "user";

    /// <summary>A device, within a Complex Subject (SSF 1.0 Section 3.3).</summary>
    public const string Device = "device";

    /// <summary>A session, within a Complex Subject (SSF 1.0 Section 3.3).</summary>
    public const string Session = "session";

    /// <summary>An application, within a Complex Subject (SSF 1.0 Section 3.3).</summary>
    public const string Application = "application";

    /// <summary>A tenant, within a Complex Subject (SSF 1.0 Section 3.3).</summary>
    public const string Tenant = "tenant";

    /// <summary>An organizational unit, within a Complex Subject (SSF 1.0 Section 3.3).</summary>
    public const string OrgUnit = "org_unit";

    /// <summary>A group, within a Complex Subject (SSF 1.0 Section 3.3).</summary>
    public const string Group = "group";
}
