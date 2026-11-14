// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// (RFC 9449 section 8) plus DPoP-specific overrides of the generic
    /// <see cref="NonceOptions.AcceptanceWindow"/> and
    /// <see cref="NonceOptions.RotationInterval"/>.
    /// </summary>
    public DPoPNonceOptions Nonce { get; set; } = new();
}
