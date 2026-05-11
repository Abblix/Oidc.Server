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
/// DPoP-specific extension of <see cref="NonceOptions"/> per RFC 9449 §8.
/// Inherits the generic primitive's <c>AcceptanceWindow</c> and
/// <c>RotationInterval</c> so DPoP can override them independently of any
/// other nonce-service consumer, and adds the per-endpoint policy that says
/// which OAuth endpoints reject DPoP proofs without a <c>nonce</c> claim
/// (responding with <c>use_dpop_nonce</c> and a fresh <c>DPoP-Nonce</c>
/// header).
/// </summary>
/// <remarks>
/// Per-endpoint flags exist only for endpoints where RFC 9449 specifies DPoP
/// applicability: the token endpoint (§5) and protected resources / UserInfo
/// (§7). RFC 9449 §6.2 explicitly disclaims DPoP at the introspection
/// endpoint and stays silent on the revocation endpoint, so flags for those
/// endpoints would be misleading non-spec promises and are intentionally
/// absent.
/// <para>
/// DPoP is the only nonce-service consumer at present, so the active
/// <c>RollingHmacNonceService</c> binds directly against this type via
/// <see cref="OidcOptions.DPoP"/>.<see cref="DPoPOptions.Nonce"/>; the
/// inherited <see cref="NonceOptions.AcceptanceWindow"/> and
/// <see cref="NonceOptions.RotationInterval"/> drive issuance. When a
/// second consumer (e.g. state-parameter validation) arrives, it brings
/// its own <see cref="NonceOptions"/>-derived options class and its own
/// service registration; the inheritance hierarchy is what lets each
/// consumer diverge on window and rotation independently.
/// </para>
/// </remarks>
public class DPoPNonceOptions : NonceOptions
{
    /// <summary>
    /// When <c>true</c>, the token endpoint rejects DPoP requests that omit a
    /// nonce claim with <c>use_dpop_nonce</c> per RFC 9449 §8. Defaults to
    /// <c>false</c>; raise to <c>true</c> to opt the deployment into
    /// nonce-protected token issuance.
    /// </summary>
    public bool RequireAtTokenEndpoint { get; set; } = false;

    /// <summary>
    /// Same as <see cref="RequireAtTokenEndpoint"/> but for the UserInfo
    /// endpoint per RFC 9449 §7. Defaults to <c>false</c>.
    /// </summary>
    public bool RequireAtUserInfoEndpoint { get; set; } = false;
}
