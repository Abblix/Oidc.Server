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
