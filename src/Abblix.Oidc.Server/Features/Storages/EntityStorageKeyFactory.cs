// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using System.Text;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Centralized factory for generating entity storage keys with consistent formatting.
/// Provides standardized key generation for all OIDC storage entities.
/// </summary>
/// <remarks>
/// A key built from a value that is itself a credential - an authorization code, a CIBA request id, a device code, a
/// user code - carries a digest of it rather than the value, so the store's own listings and the faults its client
/// raises, which quote the key, do not hand out the credential. A digest is a fixed function of the value, so every
/// node finds the same entry.
/// </remarks>
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

    /// <inheritdoc />
    public string ConsumedRequestUriKey(Uri requestUri)
        => $"Abblix.Oidc.Server:ConsumedPAR:{requestUri.OriginalString}";

    /// <summary>
    /// Generates a storage key for an authorized grant by authorization code.
    /// </summary>
    /// <param name="authorizationCode">The OAuth 2.0 authorization code.</param>
    /// <returns>A formatted storage key for the authorization grant.</returns>
    public string AuthorizedGrantKey(string authorizationCode)
        => $"Abblix.Oidc.Server:Grant:{Digest(authorizationCode)}";

    /// <summary>
    /// Generates a storage key for a backchannel authentication request by request ID.
    /// </summary>
    /// <param name="requestId">The CIBA authentication request identifier.</param>
    /// <returns>A formatted storage key for the backchannel authentication request.</returns>
    public string BackChannelAuthenticationRequestKey(string requestId)
        => $"Abblix.Oidc.Server:CIBA:{Digest(requestId)}";

    /// <summary>
    /// Generates a storage key for a device authorization request by device code.
    /// </summary>
    /// <param name="deviceCode">The device code identifier.</param>
    /// <returns>A formatted storage key for the device authorization request.</returns>
    public string DeviceAuthorizationRequestKey([Credential] string deviceCode)
        => $"Abblix.Oidc.Server:Device:{Digest(deviceCode)}";

    /// <inheritdoc />
    public string BackChannelAuthenticationNextPollKey(string requestId)
        => $"Abblix.Oidc.Server:NextPoll:CIBA:{Digest(requestId)}";

    /// <inheritdoc />
    public string DeviceAuthorizationNextPollKey([Credential] string deviceCode)
        => $"Abblix.Oidc.Server:NextPoll:Device:{Digest(deviceCode)}";

    /// <summary>
    /// Generates a storage key for mapping a user code to its device code.
    /// </summary>
    /// <param name="userCode">The user-friendly verification code.</param>
    /// <returns>A formatted storage key for the user code mapping.</returns>
    public string DeviceAuthorizationUserCodeKey([Credential] string userCode)
        => $"Abblix.Oidc.Server:UserCode:{Digest(userCode)}";

    /// <inheritdoc />
    public string UserCodeRateLimitAttemptKey([Credential] string userCode, string life, int attempt)
        => $"Abblix.Oidc.Server:RateLimit:UserCode:{Digest(userCode)}:{life}:Attempt:{attempt}";

    /// <inheritdoc />
    public string UserCodeRateLimitGenerationKey([Credential] string userCode)
        => $"Abblix.Oidc.Server:RateLimit:UserCode:{Digest(userCode)}:Generation";

    /// <inheritdoc />
    public string FailedAttemptKey(long window, int attempt)
        => $"Abblix.Oidc.Server:RateLimit:Failed:{window}:Attempt:{attempt}";

    /// <inheritdoc />
    public string AddressRateLimitAttemptKey(string clientIdentifier, long window, int attempt)
        => $"Abblix.Oidc.Server:RateLimit:Address:{clientIdentifier}:{window}:Attempt:{attempt}";

    /// <inheritdoc />
    public string SessionClientsGenerationKey(string sessionId)
        => $"Abblix.Oidc.Server:SessionClient:{sessionId}:Generation";

    /// <inheritdoc />
    public string SessionClientKey(string sessionId, string generation, int position)
        => $"Abblix.Oidc.Server:SessionClient:{sessionId}:{generation}:Position:{position}";

    /// <inheritdoc />
    public string SessionClientMarkerKey(string sessionId, string generation, string clientId)
        => $"Abblix.Oidc.Server:SessionClient:{sessionId}:{generation}:Client:{clientId}";

    /// <inheritdoc />
    public string AuthorizationValueReuseKey(string clientId, string valueKind, string valueHash)
        => $"Abblix.Oidc.Server:Reuse:{clientId}:{valueKind}:{valueHash}";

    /// <inheritdoc />
    public string LogoutConfirmationKey(string sessionId)
        => $"Abblix.Oidc.Server:LogoutConfirmation:{sessionId}";

    /// <inheritdoc />
    public string NonceSecretKey(long bucket)
        => $"Abblix.Oidc.Server:NonceSecret:{bucket}";

    /// <summary>
    /// The digest of a credential that stands for it in a storage key.
    /// </summary>
    private static string Digest(string credential)
        => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(credential)));
}
