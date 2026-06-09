// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Single source of truth for the DPoP signing-algorithm whitelist (RFC 9449 §4.2,
/// §7.1). Both the proof-validator's enforcement (it rejects proofs whose <c>alg</c>
/// header sits outside this set) and the resource-server's <c>WWW-Authenticate: DPoP
/// algs="..."</c> challenge advertisement read from here, so adding a new algorithm
/// (e.g. EdDSA when the JWS layer gains support) propagates everywhere automatically.
/// </summary>
public static class DPoPAlgorithms
{
    /// <summary>
    /// JWS algorithms accepted on a DPoP proof. <c>none</c> and HMAC-based algorithms
    /// are intentionally absent — RFC 9449 §4.2 forbids them because the embedded
    /// <c>jwk</c> header carries an asymmetric public key for verification.
    /// </summary>
    public static readonly IReadOnlySet<string> Allowed = new HashSet<string>(StringComparer.Ordinal)
    {
        SigningAlgorithms.RS256, SigningAlgorithms.RS384, SigningAlgorithms.RS512,
        SigningAlgorithms.PS256, SigningAlgorithms.PS384, SigningAlgorithms.PS512,
        SigningAlgorithms.ES256, SigningAlgorithms.ES384, SigningAlgorithms.ES512,
    };
}
