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
    /// Abstract like every other member here, deliberately, even though a body would have compiled and spared
    /// an implementation written against an earlier version. A host implements this interface in order to put
    /// its own namespace on the keys, one store shared between tenants being the usual reason, and a default
    /// member is satisfied without a compile error - so the host would keep its namespace for every other key
    /// and silently inherit ours for this one. Two tenants naming the same user would then share a cutoff, and
    /// revoking one tenant's user would revoke another's. That is invisible in the store and in any test a
    /// host would think to write, where a missing member is a compile error naming the type and the member.
    /// <para>
    /// The scope must appear in the key and must not be spelled with the enum member's name, because a rename
    /// is a refactor the compiler blesses everywhere and it would orphan every live cutoff - every suspended
    /// account and every ended session quietly working again on deploy.
    /// </para>
    /// </remarks>
    string RevocationCutoffKey(RevocationScope scope, string principal);

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
    /// Generates a storage key for the next-poll instant of a backchannel authentication request.
    /// </summary>
    /// <remarks>
    /// A top-level name of its own rather than one nested under the request's key, because an
    /// identifier is a value the host's own generator produces: nested, an identifier that happened to
    /// begin with this segment would name the request's own key and the next-poll write would land on the
    /// authentication. A key of its own, because what the polling client changes is only this instant while what the
    /// user's authentication changes is the request: a poll writing the request back to note the instant
    /// overwrote a completion that had landed since it read.
    /// </remarks>
    /// <param name="requestId">The CIBA authentication request identifier.</param>
    /// <returns>A formatted storage key for that request's poll schedule.</returns>
    string BackChannelAuthenticationNextPollKey(string requestId);

    /// <summary>
    /// Generates a storage key for the next-poll instant of a device authorization request.
    /// </summary>
    /// <remarks>
    /// A key of its own, for the same reason as its backchannel counterpart: a poll that wrote the
    /// request back to note the instant overwrote an approval that had landed since it read, and the
    /// device was told to keep waiting until the code expired.
    /// </remarks>
    /// <param name="deviceCode">The device code identifier.</param>
    /// <returns>A formatted storage key for that request's poll schedule.</returns>
    string DeviceAuthorizationNextPollKey(string deviceCode);

    /// <summary>
    /// Generates a storage key for mapping a user code to its device code.
    /// </summary>
    /// <param name="userCode">The user-friendly verification code.</param>
    /// <returns>A formatted storage key for the user code mapping.</returns>
    string DeviceAuthorizationUserCodeKey(string userCode);

    /// <summary>
    /// Generates a storage key for one failed verification attempt against a user code.
    /// </summary>
    /// <remarks>
    /// One key per attempt rather than one key holding a number: attempts are counted by how many of
    /// these exist, so failures arriving together are counted separately.
    /// </remarks>
    /// <param name="userCode">The user code being verified.</param>
    /// <param name="generation">Which life of that code the attempt belongs to, from
    /// <see cref="UserCodeRateLimitGenerationKey"/>.</param>
    /// <param name="attempt">Which attempt against that code this key stands for, counted from one.</param>
    /// <returns>A formatted storage key for that attempt.</returns>
    string UserCodeRateLimitAttemptKey(string userCode, int generation, int attempt);

    /// <summary>
    /// Generates a storage key for which life of a user code its attempt records belong to.
    /// </summary>
    /// <remarks>
    /// A verified code starts a new life rather than having its records removed, because removing them is
    /// what lets an attempt that began earlier land above the gap.
    /// </remarks>
    /// <param name="userCode">The user code being verified.</param>
    /// <returns>A formatted storage key for that code's current generation.</returns>
    string UserCodeRateLimitGenerationKey(string userCode);

    /// <summary>
    /// Generates a storage key for one failed verification attempt anywhere in the server, inside one
    /// counting window.
    /// </summary>
    /// <remarks>
    /// Not keyed by anything the caller chooses, which is the point: a guesser rotating addresses and
    /// never repeating a code escapes every other count.
    /// </remarks>
    /// <param name="window">Which counting window this attempt falls into.</param>
    /// <param name="attempt">Which attempt within that window this key stands for, counted from one.</param>
    /// <returns>A formatted storage key for that attempt.</returns>
    string FailedAttemptKey(long window, int attempt);

    /// <summary>
    /// Generates a storage key for one failed verification attempt from a client address, inside one
    /// counting window.
    /// </summary>
    /// <param name="clientIdentifier">The client identifier (typically IP address).</param>
    /// <param name="window">Which counting window this attempt falls into.</param>
    /// <param name="attempt">Which attempt within that window this key stands for, counted from one.</param>
    /// <returns>A formatted storage key for that attempt.</returns>
    string IpRateLimitAttemptKey(string clientIdentifier, long window, int attempt);

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
    /// <remarks>
    /// Leads with a segment of its own rather than with the client identifier, because an identifier is
    /// chosen at registration: leading with it, a client registered as another family's segment would spell
    /// that family's key for an awkward value.
    /// </remarks>
    /// <param name="clientId">The client the value belongs to.</param>
    /// <param name="valueKind">A discriminator for the value's role, so distinct kinds never collide.</param>
    /// <param name="valueHash">A hash of the value; the raw value is never part of the key.</param>
    /// <returns>A formatted storage key for the recorded value.</returns>
    string AuthorizationValueReuseKey(string clientId, string valueKind, string valueHash);
}
