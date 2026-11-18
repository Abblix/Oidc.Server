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
/// DPoP-specific extension of <see cref="NonceOptions"/> per RFC 9449 section 8.
/// Inherits the generic primitive's <c>AcceptanceWindow</c> and
/// <c>RotationInterval</c> so DPoP can override them independently of any
/// other nonce-service consumer, and adds the per-endpoint policy that says
/// which OAuth endpoints reject DPoP proofs without a <c>nonce</c> claim
/// (responding with <c>use_dpop_nonce</c> and a fresh <c>DPoP-Nonce</c>
/// header).
/// </summary>
/// <remarks>
/// Per-endpoint flags exist only for endpoints where RFC 9449 specifies DPoP
/// applicability: the token endpoint (section 5) and protected resources / UserInfo
/// (section 7). RFC 9449 section 6.2 explicitly disclaims DPoP at the introspection
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
    /// nonce claim with <c>use_dpop_nonce</c> per RFC 9449 section 8. Defaults to
    /// <c>false</c>; raise to <c>true</c> to opt the deployment into
    /// nonce-protected token issuance.
    /// </summary>
    public bool RequireAtTokenEndpoint { get; set; } = false;

    /// <summary>
    /// Same as <see cref="RequireAtTokenEndpoint"/> but for the UserInfo
    /// endpoint per RFC 9449 section 7. Defaults to <c>false</c>.
    /// </summary>
    public bool RequireAtUserInfoEndpoint { get; set; } = false;
}
