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
/// (message-signing, HAIP, …) extend this enum; the control mapping lives in
/// <see cref="Features.ClientInformation.SecurityProfileRequirements"/> so adding one touches a
/// single place.
/// </remarks>
public enum ClientSecurityProfile
{
    /// <summary>
    /// No bundled profile. The client is governed only by its individual metadata flags. This is the
    /// default, so existing deployments are unaffected until a profile is explicitly selected on a
    /// client.
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
