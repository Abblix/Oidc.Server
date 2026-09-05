// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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