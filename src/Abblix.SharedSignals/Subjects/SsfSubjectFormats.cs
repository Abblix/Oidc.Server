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

using Abblix.SecurityEvents.Subjects;

namespace Abblix.SharedSignals.Subjects;

/// <summary>
/// The Identifier Format names SSF 1.0 adds on top of the RFC 9493 registry: the Complex Subject
/// (Section 3.3) and the additional formats of Section 3.5. Named "Ssf" to keep them apart from
/// the RFC 9493 <see cref="SubjectFormats"/> a consumer imports alongside.
/// </summary>
public static class SsfSubjectFormats
{
    /// <summary>
    /// The Complex Subject: a set of Simple Subject Members that together refer to exactly one
    /// Subject Principal (SSF 1.0 Sections 3.3, 3.3.1).
    /// </summary>
    public const string Complex = "complex";

    /// <summary>
    /// A JWT identified by its "iss" and "jti" claims (SSF 1.0 Section 3.5.1).
    /// </summary>
    public const string JwtId = "jwt_id";

    /// <summary>
    /// A SAML 2.0 assertion identified by its Issuer and ID values (SSF 1.0 Section 3.5.2).
    /// </summary>
    public const string SamlAssertionId = "saml_assertion_id";

    /// <summary>
    /// An array of IP addresses observed by the transmitter (SSF 1.0 Section 3.5.3).
    /// </summary>
    public const string IpAddresses = "ip-addresses";

    /// <summary>
    /// The formats above mapped to the subtypes modelling them, in the shape
    /// <see cref="SubjectIdentifierJsonConverter(IReadOnlyDictionary{string, Type})"/> takes:
    /// build the converter with this map and place it in the serializer options, and every SSF
    /// reading path understands the whole Section 3 vocabulary.
    /// </summary>
    public static IReadOnlyDictionary<string, Type> Registrations { get; } =
        new Dictionary<string, Type>(StringComparer.Ordinal)
        {
            [Complex] = typeof(ComplexSubject),
            [JwtId] = typeof(JwtIdSubject),
            [SamlAssertionId] = typeof(SamlAssertionIdSubject),
            [IpAddresses] = typeof(IpAddressesSubject),
        };
}
