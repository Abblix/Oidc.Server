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

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// The product of a successfully validated DPoP proof: the parsed JWT (so callers can read
/// claims the validator does not consume itself, e.g. <c>nonce</c>), the public-only JWK
/// extracted from the proof's <c>jwk</c> header, its base64url-encoded RFC 7638 JWK
/// Thumbprint (the value that goes into <c>cnf.jkt</c> on the issued access token and
/// matches against <c>dpop_jkt</c>), the proof-unique <c>jti</c> for downstream replay
/// protection, and the <c>iat</c> the proof claims to have been signed at.
/// </summary>
/// <param name="Token">The parsed proof JWT. The validator already produced this object
/// internally; carrying it through saves callers a re-parse when they need claims outside
/// the validator's contract (notably DPoP-Nonce checks layered on top).</param>
/// <param name="ProofKey">The public-only JWK from the proof header.</param>
/// <param name="ProofKeyThumbprint">RFC 7638 base64url-encoded JWK Thumbprint of
/// <paramref name="ProofKey"/>. This is the value that goes into <c>cnf.jkt</c> on the issued
/// access token (RFC 9449 §6.1) - the role-name «proof key thumbprint» reflects the
/// protocol-level meaning, while the wire-level cnf-member retains the RFC's
/// <c>jkt</c> spelling.</param>
/// <param name="JwtId">The <c>jti</c> claim of the proof. The validator does not check it
/// against any cache; the layered replay-cache slice consumes this value.</param>
/// <param name="IssuedAt">The <c>iat</c> claim of the proof, parsed from the JWT
/// numeric-date.</param>
public sealed record Proof(
    JsonWebToken Token,
    JsonWebKey ProofKey,
    string ProofKeyThumbprint,
    string JwtId,
    DateTimeOffset IssuedAt);
