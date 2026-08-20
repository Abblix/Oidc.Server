// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// A named bundle of security controls a client is held to. Selecting a profile forces the whole
/// bundle on the client at once and prevents an individual toggle from silently weakening it, which
/// is what makes a client conformant with one setting instead of several hand-tuned flags.
/// </summary>
/// <remarks>
/// Deliberately a closed enum rather than a set of independent booleans: the value set is fixed by
/// the library (a host cannot invent a profile), and a single discriminator is what the
/// effective-policy lookup and the fail-loud self-consistency check both key on. New profiles
/// (message-signing, HAIP, ...) extend this enum; the control mapping lives in
/// <see cref="Features.ClientInformation.SecurityProfileRequirements"/> so adding one touches a
/// single place.
/// </remarks>
public enum ClientSecurityProfile
{
    /// <summary>
    /// No bundled profile: the client is governed only by its individual metadata flags. As a client's
    /// explicit value this is an opt-out that overrides the server-wide default; as the server-wide
    /// <see cref="Configuration.OidcOptions.DefaultSecurityProfile"/> it imposes nothing. A client that
    /// states no preference leaves its profile unset (<c>null</c>) rather than selecting this.
    /// </summary>
    None = 0,

    /// <summary>
    /// The FAPI 2.0 Security Profile. Forces PKCE restricted to <c>S256</c>, Pushed Authorization
    /// Requests, sender-constrained (DPoP) tokens, and the authorization-code response type only,
    /// regardless of the client's individual toggles. This is the prerequisite for running the
    /// OpenID Foundation FAPI 2.0 conformance suite against the client.
    /// </summary>
    Fapi2,
}
