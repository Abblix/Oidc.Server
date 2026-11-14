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
/// Each member carries its number explicitly, because a host persists the number: a member inserted, or a number
/// changed, would change what every stored client means.
///
/// Deliberately a closed enum rather than a set of independent booleans: the value set is fixed by
/// the library (a host cannot invent a profile), and a single discriminator is what the
/// effective-policy lookup and the fail-loud self-consistency check both key on. New profiles
/// (HAIP, ...) extend this enum; the control mapping lives in
/// <see cref="Features.ClientInformation.SecurityProfileRequirements"/> so adding one touches a
/// single place.
/// </remarks>
public enum ClientSecurityProfile
{
    /// <summary>
    /// No bundled profile: nothing is demanded beyond the client's individual metadata flags. As a
    /// client's explicit value it therefore adds nothing to whatever the deployment already demands,
    /// and takes nothing away; as the server-wide
    /// <see cref="Features.MultiTenancy.TenantDefinition.DefaultSecurityProfile"/> it demands nothing of anyone. A
    /// client that states no preference leaves its profile unset (<c>null</c>) rather than selecting
    /// this.
    /// </summary>
    None = 0,

    /// <summary>
    /// The FAPI 2.0 Security Profile. Forces PKCE restricted to <c>S256</c>, Pushed Authorization
    /// Requests, sender-constrained (DPoP) tokens, and the authorization-code response type only,
    /// regardless of the client's individual toggles. This is the prerequisite for running the
    /// OpenID Foundation FAPI 2.0 conformance suite against the client.
    /// </summary>
    Fapi2 = 1,

    /// <summary>
    /// The controls of the FAPI 1.0 Advanced Security Profile (Part 2 sections 5.2.2, 8.6, 8.6.1 and 8.9, and the Part 1
    /// section 5.2.2 provisions it takes in) that the library enforces: a signed request object on every authorization
    /// request, only the parameters inside it used, its <c>nbf</c> and <c>exp</c> bounded to 60 minutes and its
    /// audience the issuer; an authorization response the server signs (<c>code id_token</c>, or <c>code</c> with the
    /// <c>jwt</c> response mode); a nonce with the <c>openid</c> scope and state without it; PKCE with S256 on a pushed
    /// request; exact https redirect URIs; a jwks_uri over TLS; only PS256 and ES256 signatures and no RSA1_5
    /// encryption, in what the client signs or encrypts for the server and the server for the client;
    /// sender-constrained access tokens; and confidential clients authenticating by mutual TLS or a private key JWT,
    /// whose credential and client_id name the same client. PKCE on a request sent directly and Pushed Authorization
    /// Requests are left to the client's own settings, since the profile asks PKCE only of a pushed request and lets the
    /// server choose whether to offer PAR.
    /// </summary>
    /// <remarks>
    /// Appended after <see cref="Fapi2"/> because a host persists the numeric value: a member inserted before it
    /// would change what every stored client means.
    /// </remarks>
    Fapi1Advanced = 2,

    /// <summary>
    /// The FAPI 2.0 Security Profile with the authorization request signing of FAPI 2.0 Message Signing section 5.3.1:
    /// every authorization request pushed as a signed request object, its audience the issuer, its <c>nbf</c> no more
    /// than 60 minutes in the past and its <c>exp</c> no more than 60 minutes after the <c>nbf</c>.
    /// </summary>
    /// <remarks>
    /// One of three values because section 5.1 of that specification expects software "to conform to each of the
    /// methods separately", with "separate conformance testing options" for signed requests and signed responses.
    /// </remarks>
    Fapi2SignedAuthorizationRequests = 3,

    /// <summary>
    /// The FAPI 2.0 Security Profile with the authorization response signing of FAPI 2.0 Message Signing section 5.4.1:
    /// every authorization response issued as a signed JWT in a JARM response mode.
    /// </summary>
    Fapi2SignedAuthorizationResponses = 4,

    /// <summary>
    /// FAPI 2.0 Message Signing whole: the FAPI 2.0 Security Profile with both signed authorization requests
    /// (section 5.3.1) and signed authorization responses (section 5.4.1). Signed introspection responses (section
    /// 5.5.1) need no profile, since they are signed for any client asking for the JWT format.
    /// </summary>
    Fapi2MessageSigning = 5,
}
