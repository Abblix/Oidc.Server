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

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Values for the Subject Identifier "format" member (RFC 9493 Section 3), naming the set of rules
/// by which a subject is encoded; the discriminator when deserializing a
/// <see cref="SubjectIdentifier"/> into the correct concrete subtype. Two families live here, each
/// constant naming its own: the formats of the IANA "Security Event Subject Identifier Formats"
/// registry (RFC 9493 Section 8.1.2), and the extensions OpenID Shared Signals Framework 1.0
/// defines on top of that registry (SSF 1.0 Sections 3.3, 3.5) - which its Section 11 asks IANA to
/// register, a registration the registry does not yet show.
/// </summary>
public static class SubjectFormats
{
    /// <summary>
    /// An account at a service provider, identified by an "acct" URI (RFC 9493 Section 3.2.1).
    /// Maps to <see cref="AccountSubject"/>.
    /// </summary>
    public const string Account = "account";

    /// <summary>
    /// An email address (RFC 9493 Section 3.2.2). Maps to <see cref="EmailSubject"/>.
    /// </summary>
    public const string Email = "email";

    /// <summary>
    /// An issuer and subject pair, analogous to the JWT "iss" and "sub" claims
    /// (RFC 9493 Section 3.2.3). Maps to <see cref="IssSubSubject"/>.
    /// </summary>
    public const string IssSub = "iss_sub";

    /// <summary>
    /// A string carrying no semantics beyond identifying the subject (RFC 9493 Section 3.2.4).
    /// Maps to <see cref="OpaqueSubject"/>.
    /// </summary>
    public const string Opaque = "opaque";

    /// <summary>
    /// A telephone number in E.164 form (RFC 9493 Section 3.2.5).
    /// Maps to <see cref="PhoneNumberSubject"/>.
    /// </summary>
    public const string PhoneNumber = "phone_number";

    /// <summary>
    /// A Decentralized Identifier URL (RFC 9493 Section 3.2.6). Maps to <see cref="DidSubject"/>.
    /// </summary>
    public const string Did = "did";

    /// <summary>
    /// A Uniform Resource Identifier, with no assumption about its scheme or reachability
    /// (RFC 9493 Section 3.2.7). Maps to <see cref="UriSubject"/>.
    /// </summary>
    public const string Uri = "uri";

    /// <summary>
    /// A list of Subject Identifiers that all identify the same entity
    /// (RFC 9493 Section 3.2.8). Maps to <see cref="AliasesSubject"/>.
    /// </summary>
    public const string Aliases = "aliases";

    /// <summary>
    /// SSF 1.0 extension, not an IANA registration. A set of Simple Subject Members that together
    /// refer to exactly one Subject Principal (SSF 1.0 Section 3.3).
    /// Maps to <see cref="ComplexSubject"/>.
    /// </summary>
    public const string Complex = "complex";

    /// <summary>
    /// SSF 1.0 extension, not an IANA registration. A JWT identified by its "iss" and "jti"
    /// claims (SSF 1.0 Section 3.5.1). Maps to <see cref="JwtIdSubject"/>.
    /// </summary>
    public const string JwtId = "jwt_id";

    /// <summary>
    /// SSF 1.0 extension, not an IANA registration. A SAML 2.0 assertion identified by its Issuer
    /// and ID values (SSF 1.0 Section 3.5.2). Maps to <see cref="SamlAssertionIdSubject"/>.
    /// </summary>
    public const string SamlAssertionId = "saml_assertion_id";

    /// <summary>
    /// SSF 1.0 extension, not an IANA registration. An array of IP addresses observed by the
    /// transmitter (SSF 1.0 Section 3.5.3). Maps to <see cref="IpAddressesSubject"/>.
    /// </summary>
    public const string IpAddresses = "ip-addresses";
}
