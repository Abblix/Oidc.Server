// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Configuration options for software statement validation per RFC 7591 Section 2.3.
/// Software statements are signed JWTs issued by a third-party authority asserting
/// metadata values about the client software.
/// </summary>
public record SoftwareStatementOptions
{
    /// <summary>
    /// Whether a software statement is required for client registration.
    /// When <c>true</c>, registration requests without a software_statement will be rejected.
    /// </summary>
    public bool RequireSoftwareStatement { get; set; } = false;

    /// <summary>
    /// The trusted issuers whose software statements are accepted.
    /// Each issuer provides a JWKS endpoint for signature verification.
    /// </summary>
    public TrustedIssuer[] TrustedIssuers { get; set; } = [];

    /// <summary>
    /// Optional set of approved software identifiers. If non-empty, only software statements
    /// with a software_id claim matching one of these values will be accepted.
    /// When empty, all software IDs from trusted issuers are accepted.
    /// </summary>
    public HashSet<string> ApprovedSoftwareIds { get; set; } = [];
}
