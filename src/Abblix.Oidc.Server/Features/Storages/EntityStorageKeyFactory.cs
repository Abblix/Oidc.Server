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
/// Centralized factory for generating entity storage keys with consistent formatting.
/// Provides standardized key generation for all OIDC storage entities.
/// </summary>
public class EntityStorageKeyFactory : IEntityStorageKeyFactory
{
    /// <summary>
    /// Generates a storage key for JWT status by JWT ID.
    /// </summary>
    /// <param name="jwtId">The JSON Web Token identifier.</param>
    /// <returns>A formatted storage key for the JWT status.</returns>
    public string JsonWebTokenStatusKey(string jwtId)
        => $"Abblix.Oidc.Server:JWT:{jwtId}";

    /// <summary>
    /// Generates a storage key for a revocation cutoff recorded against a subject or a session.
    /// </summary>
    /// <param name="scope">Whether the principal is an end user or a single session.</param>
    /// <param name="principal">The subject identifier or the session identifier.</param>
    /// <returns>A formatted storage key for the cutoff.</returns>
    public string RevocationCutoffKey(RevocationScope scope, string principal)
        => $"Abblix.Oidc.Server:Revoked:{NameOf(scope)}:{principal}";

    /// <summary>
    /// The wire name of a revocation scope, fixed independently of the enum member's name so that renaming
    /// the member cannot orphan the cutoffs already in the store.
    /// </summary>
    private static string NameOf(RevocationScope scope) => scope switch
    {
        RevocationScope.Subject => "subject",
        RevocationScope.Session => "session",
        _ => throw new ArgumentOutOfRangeException(
            nameof(scope), scope, $"No storage key is defined for this {nameof(RevocationScope)}."),
    };

    /// <summary>
    /// Generates a storage key for an authorization request by URI.
    /// </summary>
    /// <param name="requestUri">The pushed authorization request URI.</param>
    /// <returns>A formatted storage key for the authorization request.</returns>
    public string AuthorizationRequestKey(Uri requestUri)
        => $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}";

    /// <summary>
    /// Generates a storage key for an authorized grant by authorization code.
    /// </summary>
    /// <param name="authorizationCode">The OAuth 2.0 authorization code.</param>
    /// <returns>A formatted storage key for the authorization grant.</returns>
    public string AuthorizedGrantKey(string authorizationCode)
        => $"Abblix.Oidc.Server:Grant:{authorizationCode}";

    /// <summary>
    /// Generates a storage key for a backchannel authentication request by request ID.
    /// </summary>
    /// <param name="requestId">The CIBA authentication request identifier.</param>
    /// <returns>A formatted storage key for the backchannel authentication request.</returns>
    public string BackChannelAuthenticationRequestKey(string requestId)
        => $"Abblix.Oidc.Server:CIBA:{requestId}";

    /// <summary>
    /// Generates a storage key for a device authorization request by device code.
    /// </summary>
    /// <param name="deviceCode">The device code identifier.</param>
    /// <returns>A formatted storage key for the device authorization request.</returns>
    public string DeviceAuthorizationRequestKey(string deviceCode)
        => $"Abblix.Oidc.Server:Device:{deviceCode}";

    /// <summary>
    /// Generates a storage key for mapping a user code to its device code.
    /// </summary>
    /// <param name="userCode">The user-friendly verification code.</param>
    /// <returns>A formatted storage key for the user code mapping.</returns>
    public string DeviceAuthorizationUserCodeKey(string userCode)
        => $"Abblix.Oidc.Server:UserCode:{userCode}";

    /// <summary>
    /// Generates a storage key for rate limiting user code verification attempts.
    /// </summary>
    /// <param name="userCode">The user code being verified.</param>
    /// <returns>A formatted storage key for the user code rate limit state.</returns>
    public string UserCodeRateLimitKey(string userCode)
        => $"Abblix.Oidc.Server:RateLimit:UserCode:{userCode}";

    /// <summary>
    /// Generates a storage key for rate limiting by IP address or client identifier.
    /// </summary>
    /// <param name="clientIdentifier">The client identifier (typically IP address).</param>
    /// <returns>A formatted storage key for the IP rate limit state.</returns>
    public string IpRateLimitKey(string clientIdentifier)
        => $"Abblix.Oidc.Server:RateLimit:IP:{clientIdentifier}";

    /// <summary>
    /// Generates a storage key for the registration access token binding of a client (RFC 7592).
    /// </summary>
    /// <param name="clientId">The identifier of the registered client.</param>
    /// <returns>A formatted storage key for the client's current registration-access-token jti.</returns>
    public string RegistrationAccessTokenKey(string clientId)
        => $"Abblix.Oidc.Server:RegistrationAccessToken:{clientId}";

    /// <inheritdoc />
    public string AuthorizationValueReuseKey(string clientId, string valueKind, string valueHash)
        => $"Abblix.Oidc.Server:{clientId}:Reuse:{valueKind}:{valueHash}";
}
