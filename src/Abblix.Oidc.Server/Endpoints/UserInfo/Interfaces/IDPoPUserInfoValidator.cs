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
/// Validates the DPoP-binding contract on a UserInfo request per RFC 9449 §7.1: when the
/// inbound access token is DPoP-bound (carries <c>cnf.jkt</c>), the request MUST present
/// <c>Authorization: DPoP &lt;token&gt;</c> together with a valid <c>DPoP</c> header
/// proof whose key thumbprint matches the access token's <c>cnf.jkt</c> and whose
/// <c>ath</c> claim equals <c>Base64Url(SHA-256(access_token))</c>. Unbound (Bearer)
/// access tokens passed via the Bearer scheme bypass the check.
/// </summary>
public interface IDPoPUserInfoValidator
{
    /// <summary>
    /// Returns <c>null</c> on success, an <see cref="OidcError"/> describing the binding
    /// failure otherwise. The typed subclasses <see cref="InvalidDPoPProofError"/> and
    /// <see cref="UseDPoPNonceError"/> let the response formatter pattern-match for the
    /// RFC 9449 §7.1 <c>WWW-Authenticate: DPoP</c> challenge or the §8 nonce response
    /// header attachment.
    /// </summary>
    /// <param name="clientRequest">Carries the <c>Authorization</c> scheme + token plus
    /// the optional <c>DPoP</c> proof header.</param>
    /// <param name="accessToken">The parsed access-token JWT whose <c>cnf.jkt</c>
    /// (when present) the proof must match.</param>
    /// <param name="rawAccessToken">The original on-the-wire access-token string used
    /// to compute <c>ath = Base64Url(SHA-256(access_token))</c>.</param>
    Task<OidcError?> ValidateAsync(
        ClientRequest clientRequest,
        JsonWebToken accessToken,
        string rawAccessToken);
}
