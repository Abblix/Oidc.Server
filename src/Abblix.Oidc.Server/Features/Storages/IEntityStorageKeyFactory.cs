// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Tokens.Revocation;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Defines a contract for generating entity storage keys with consistent formatting.
/// Provides standardized key generation for all OIDC storage entities.
/// </summary>
public interface IEntityStorageKeyFactory
{
    /// <summary>
    /// Generates a storage key for JWT status by JWT ID.
    /// </summary>
    /// <param name="jwtId">The JSON Web Token identifier.</param>
    /// <returns>A formatted storage key for the JWT status.</returns>
    string JsonWebTokenStatusKey(string jwtId);

    /// <summary>
    /// Names the revocation cutoff recorded against a subject or a session.
    /// </summary>
    /// <param name="scope">Whether the principal is an end user or a single session.</param>
    /// <param name="principal">The subject identifier or the session identifier.</param>
    /// <returns>A formatted storage key for the cutoff.</returns>
    /// <remarks>
    /// Carries its own implementation because this interface has shipped: a host that implements it to
    /// namespace its own store keeps compiling, and overrides this member when it wants the cutoff named
    /// its way too.
    /// </remarks>
    string RevocationCutoffKey(RevocationScope scope, string principal)
        => $"Abblix.Oidc.Server:Revoked:{scope}:{principal}";

    /// <summary>
    /// Generates a storage key for an authorization request by URI.
    /// </summary>
    /// <param name="requestUri">The pushed authorization request URI.</param>
    /// <returns>A formatted storage key for the authorization request.</returns>
    string AuthorizationRequestKey(Uri requestUri);

    /// <summary>
    /// Generates a storage key for an authorized grant by authorization code.
    /// </summary>
    /// <param name="authorizationCode">The OAuth 2.0 authorization code.</param>
    /// <returns>A formatted storage key for the authorization grant.</returns>
    string AuthorizedGrantKey(string authorizationCode);

    /// <summary>
    /// Generates a storage key for a backchannel authentication request by request ID.
    /// </summary>
    /// <param name="requestId">The CIBA authentication request identifier.</param>
    /// <returns>A formatted storage key for the backchannel authentication request.</returns>
    string BackChannelAuthenticationRequestKey(string requestId);

    /// <summary>
    /// Generates a storage key for a device authorization request by device code.
    /// </summary>
    /// <param name="deviceCode">The device code identifier.</param>
    /// <returns>A formatted storage key for the device authorization request.</returns>
    string DeviceAuthorizationRequestKey(string deviceCode);

    /// <summary>
    /// Generates a storage key for mapping a user code to its device code.
    /// </summary>
    /// <param name="userCode">The user-friendly verification code.</param>
    /// <returns>A formatted storage key for the user code mapping.</returns>
    string DeviceAuthorizationUserCodeKey(string userCode);

    /// <summary>
    /// Generates a storage key for rate limiting user code verification attempts.
    /// </summary>
    /// <param name="userCode">The user code being verified.</param>
    /// <returns>A formatted storage key for the user code rate limit state.</returns>
    string UserCodeRateLimitKey(string userCode);

    /// <summary>
    /// Generates a storage key for rate limiting by IP address or client identifier.
    /// </summary>
    /// <param name="clientIdentifier">The client identifier (typically IP address).</param>
    /// <returns>A formatted storage key for the IP rate limit state.</returns>
    string IpRateLimitKey(string clientIdentifier);

    /// <summary>
    /// Generates a storage key for the registration access token binding of a client (RFC 7592).
    /// </summary>
    /// <param name="clientId">The identifier of the registered client.</param>
    /// <returns>A formatted storage key for the client's current registration-access-token jti.</returns>
    string RegistrationAccessTokenKey(string clientId);

    /// <summary>
    /// Generates a storage key for reuse detection of an authorization request value (a PKCE
    /// <c>code_challenge</c> or an OpenID Connect <c>nonce</c>), scoped to a client and the value's kind.
    /// </summary>
    /// <param name="clientId">The client the value belongs to.</param>
    /// <param name="valueKind">A discriminator for the value's role, so distinct kinds never collide.</param>
    /// <param name="valueHash">A hash of the value; the raw value is never part of the key.</param>
    /// <returns>A formatted storage key for the recorded value.</returns>
    string AuthorizationValueReuseKey(string clientId, string valueKind, string valueHash);
}
