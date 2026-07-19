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

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// ASN.1 tag values for GeneralName types in Subject Alternative Name extension (RFC 5280).
/// These values correspond to the context-specific tags used in X.509 certificate SAN extensions.
/// </summary>
internal enum GeneralNameTag
{
    /// <summary>
    /// OtherName - Used for custom name types not covered by standard GeneralName types.
    /// </summary>
    OtherName = 0,

    /// <summary>
    /// Rfc822Name - Email address in RFC 822 format (user@domain.com).
    /// </summary>
    Rfc822Name = 1,

    /// <summary>
    /// DnsName - Domain Name System name (e.g., example.com, *.example.com).
    /// </summary>
    DnsName = 2,

    /// <summary>
    /// X400Address - X.400 address (legacy email system, rarely used).
    /// </summary>
    X400Address = 3,

    /// <summary>
    /// DirectoryName - X.500 Distinguished Name in directory format.
    /// </summary>
    DirectoryName = 4,

    /// <summary>
    /// EdiPartyName - EDI (Electronic Data Interchange) party name (rarely used).
    /// </summary>
    EdiPartyName = 5,

    /// <summary>
    /// UniformResourceIdentifier - URI in any valid scheme (https://, ldap://, etc.).
    /// </summary>
    UniformResourceIdentifier = 6,

    /// <summary>
    /// IpAddress - IPv4 or IPv6 address encoded as octets.
    /// </summary>
    IpAddress = 7,

    /// <summary>
    /// RegisteredId - Object Identifier (OID) registered in ISO/ITU standards.
    /// </summary>
    RegisteredId = 8,
}