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

using Abblix.Oidc.Server.Features.Nonces;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Configuration options for OAuth 2.0 DPoP (RFC 9449), covering the proof
/// validator's <c>iat</c> tolerance and DPoP-specific nonce policy. The
/// nonce sub-section inherits from the generic <see cref="NonceOptions"/>
/// so DPoP can configure stricter values independently of other nonce-service
/// consumers without duplicating field definitions.
/// </summary>
public class DPoPOptions
{
    /// <summary>
    /// Tolerance window applied to the <c>iat</c> claim of an incoming DPoP proof: the
    /// proof is accepted if its <c>iat</c> falls within this duration of the server's
    /// current time. Default is 1 minute. Tighter than the JWT <c>exp</c> machinery
    /// because DPoP proofs have no expiration claim - <c>iat</c> bounds them.
    /// </summary>
    public TimeSpan IssuedAtTolerance { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// DPoP-specific nonce configuration: per-endpoint require-nonce policy
    /// (RFC 9449 §8) plus DPoP-specific overrides of the generic
    /// <see cref="NonceOptions.AcceptanceWindow"/> and
    /// <see cref="NonceOptions.RotationInterval"/>.
    /// </summary>
    public DPoPNonceOptions Nonce { get; set; } = new();
}
