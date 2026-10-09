// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Oidc;

/// <summary>
/// The names of claims this library writes or reads that the IANA JSON Web Token Claims registry does not hold.
/// The registered names are in <see cref="Abblix.Jwt.IanaClaimTypes"/>.
/// </summary>
public static class OidcClaimTypes
{
    /// <summary>
    /// The 'idp' claim represents the identity provider that authenticated the end user.
    /// </summary>
    public const string IdentityProvider = "idp";

    /// <summary>
    /// The 'requested_claims' claim represents the specific claims requested by the client.
    /// </summary>
    public const string RequestedClaims = "requested_claims";

    /// <summary>
    /// The identifier of the backchannel authentication request this ID Token answers, carried so a
    /// push notification cannot be replayed against a different request.
    /// </summary>
    /// <remarks>
    /// CIBA Core 1.0 Section 10.3.1 phrases this alongside the hashes - "the OP MUST include the hash
    /// value of the Access Token and the auth_req_id ... using the at_hash and
    /// urn:openid:params:jwt:claim:auth_req_id claims respectively" - but its own worked example beside
    /// that sentence carries the identifier VERBATIM, matching the <c>auth_req_id</c> field of the same
    /// notification body. The example is what a client compares against, and its own requirement is to
    /// check that this claim MATCHES the identifier it asked about, which a hash would not let it do.
    /// <para>
    /// Required in push mode only, which the same paragraph says outright. Poll and ping clients redeem
    /// at the token endpoint holding the identifier already.
    /// </para>
    /// </remarks>
    public const string AuthenticationRequestId = "urn:openid:params:jwt:claim:auth_req_id";

    /// <summary>
    /// The hash of the refresh token delivered beside this ID Token, computed the same way
    /// <see cref="Abblix.Jwt.IanaClaimTypes.AtHash"/> is.
    /// </summary>
    /// <remarks>
    /// CIBA Core 1.0 Section 10.3.1: "In case a Refresh Token is sent to the Client, the hash value of
    /// it MUST also be added to the ID token using the urn:openid:params:jwt:claim:rt_hash claim", and
    /// the same sentence points at OpenID Connect Core 1.0 Section 3.1.3.6 for the calculation - the one
    /// <c>at_hash</c> uses. Required in push mode only, which is what the paragraph says - it does not
    /// forbid the claim elsewhere - and only when a refresh token is actually sent.
    /// </remarks>
    public const string RefreshTokenHash = "urn:openid:params:jwt:claim:rt_hash";

    /// <summary>
    /// "grant_id" - Abblix private claim (RFC 7519 Section 4.3) naming the refresh token family an access or
    /// refresh token was minted inside: the family the grant it was issued under carried, or the one started for a
    /// request issuing a refresh token. An ID token carries none. It binds those tokens into a single lineage (a "token family" in RFC 9700
    /// terms): a first-issued refresh token starts a new grant, and each rotation carries the same value forward.
    /// It lets a detected replay revoke the whole family in one registry write. A token exercising no such
    /// authority carries no value. No IANA-registered claim captures per-grant refresh-token lineage. The value is
    /// random and opaque, so a resource server reading it from an access token learns only which tokens share a
    /// grant. See RFC 9700 Section 4.14.2.
    /// </summary>
    public const string GrantId = "grant_id";
}
