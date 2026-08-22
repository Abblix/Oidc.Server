// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// RFC 8705 metadata for tls_client_auth method. Defines match rules for
/// Subject DN and/or Subject Alternative Name entries.
/// </summary>
public record TlsClientAuthOptions
{
    /// <summary>
    /// Exact Subject Distinguished Name (RFC 4514) that must be present on client cert.
    /// </summary>
    public string? SubjectDn { get; init; }

    /// <summary>
    /// Required DNS SAN entries.
    /// </summary>
    public string[]? SanDns { get; init; }

    /// <summary>
    /// Required URI SAN entries.
    /// </summary>
    public Uri[]? SanUris { get; init; }

    /// <summary>
    /// Required IP SAN entries (string representation).
    /// </summary>
    public string[]? SanIps { get; init; }

    /// <summary>
    /// Required email SAN entries (RFC822Name).
    /// </summary>
    public string[]? SanEmails { get; init; }
}

