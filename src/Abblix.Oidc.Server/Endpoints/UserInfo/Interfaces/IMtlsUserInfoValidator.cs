// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;

/// <summary>
/// Validates the mutual-TLS certificate-binding contract on a UserInfo request per
/// RFC 8705 §3: when the inbound access token is certificate-bound (carries
/// <c>cnf.x5t#S256</c>), the protected resource MUST obtain the client certificate used for
/// mutual TLS and verify that its SHA-256 thumbprint matches the bound value, rejecting the
/// request otherwise. Unbound access tokens bypass the check. Sibling of
/// <see cref="IDPoPUserInfoValidator"/>: the two proof-of-possession mechanisms (DPoP
/// <c>cnf.jkt</c> and mTLS <c>cnf.x5t#S256</c>) are independent and a token carrying both
/// must satisfy each.
/// </summary>
public interface IMtlsUserInfoValidator
{
    /// <summary>
    /// Returns <c>null</c> when the binding holds (or the token is not certificate-bound),
    /// and an <see cref="OidcError"/> with <c>invalid_token</c> when the token is bound but
    /// the presented certificate is absent or its thumbprint does not match
    /// <c>cnf.x5t#S256</c> (RFC 8705 §3 - HTTP 401, per RFC 6750).
    /// </summary>
    /// <param name="clientRequest">Carries the client certificate presented on the mutual-TLS
    /// connection (when any).</param>
    /// <param name="accessToken">The parsed access-token JWT whose <c>cnf.x5t#S256</c>
    /// (when present) the presented certificate must match.</param>
    OidcError? Validate(ClientRequest clientRequest, JsonWebToken accessToken);
}
