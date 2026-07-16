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

namespace Abblix.Jwt;

/// <summary>
/// One version of a custodian-held key: its public half and when the custodian created that version. The
/// public key carries the version-specific <c>kid</c> that routes a private operation back to this exact
/// version, so publishing a key's versions lets a client verify a signature made by any of them and lets the
/// server unwrap a JWE encrypted to any of them. The creation time is what a rotation policy reads to hold a
/// freshly minted version as announced-but-not-yet-signing until client JWKS caches catch up (the propagation
/// window), and to keep a superseded version published until its tokens expire.
/// </summary>
/// <param name="PublicKey">The public-only key material for this version, with its version-specific <c>kid</c>.</param>
/// <param name="CreatedAt">When the custodian created this version. A custodian that does not track a creation
/// time reports <see cref="DateTimeOffset.MinValue"/>, which a rotation policy treats as "always past the
/// propagation window", so a single non-rotating key is always eligible to sign.</param>
public sealed record KeyVersion(JsonWebKey PublicKey, DateTimeOffset CreatedAt);
