// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Single source of truth for the DPoP signing-algorithm whitelist (RFC 9449 section 4.2,
/// section 7.1). Both the proof-validator's enforcement (it rejects proofs whose <c>alg</c>
/// header sits outside this set) and the resource-server's <c>WWW-Authenticate: DPoP
/// algs="..."</c> challenge advertisement read from here, so adding a new algorithm
/// (e.g. EdDSA when the JWS layer gains support) propagates everywhere automatically.
/// </summary>
public static class DPoPAlgorithms
{
    /// <summary>
    /// JWS algorithms accepted on a DPoP proof. <c>none</c> and HMAC-based algorithms
    /// are intentionally absent - RFC 9449 section 4.2 forbids them because the embedded
    /// <c>jwk</c> header carries an asymmetric public key for verification.
    /// </summary>
    public static readonly IReadOnlySet<string> Allowed = new HashSet<string>(StringComparer.Ordinal)
    {
        SigningAlgorithms.RS256, SigningAlgorithms.RS384, SigningAlgorithms.RS512,
        SigningAlgorithms.PS256, SigningAlgorithms.PS384, SigningAlgorithms.PS512,
        SigningAlgorithms.ES256, SigningAlgorithms.ES384, SigningAlgorithms.ES512,
    };

    /// <summary>
    /// The algorithms of <see cref="Allowed"/> <paramref name="profile"/> admits: FAPI 1.0 Part 2 section 8.6, FAPI 2.0
    /// section 5.4.1, "when creating or processing JWTs".
    /// </summary>
    /// <param name="profile">The controls in force for the client presenting the proof.</param>
    public static IReadOnlyCollection<string> AdmittedBy(SecurityProfileRequirements profile)
        => Allowed.Where(profile.PermitsSigningAlgorithm).ToArray();

    /// <summary>
    /// The algorithms a <c>WWW-Authenticate: DPoP</c> challenge answering <paramref name="error"/> advertises (RFC 9449
    /// section 7.1, <c>algs</c>): those the profile of the client the presented token was issued to admits where the
    /// error names them, else those the tenant's profile admits.
    /// </summary>
    /// <param name="error">The refusal the challenge answers.</param>
    /// <param name="tenant">The tenant the request is served at.</param>
    public static IReadOnlyCollection<string> Advertised(OidcError error, TenantDefinition tenant)
        => error switch
        {
            InvalidDPoPProofError { AlgorithmsAdmitted: { } admitted } => admitted,
            UseDPoPNonceError { AlgorithmsAdmitted: { } admitted } => admitted,
            _ => AdmittedBy(SecurityProfileRequirements.For(tenant, client: null)),
        };
}
