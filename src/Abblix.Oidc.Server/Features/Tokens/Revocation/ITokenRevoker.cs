// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Revokes every token issued to an end user, or within one session, up to a moment.
/// </summary>
/// <remarks>
/// The library owns the enforcement and the host owns the occasion. An account suspension, a password change
/// or an administrator signing a user out of everything are all host events this server never learns of, so
/// this is where the host says when.
/// <para>
/// RFC 7009 is not this surface: that endpoint revokes one token a client presents, which is a different act
/// with a different actor. Nothing here is reachable by a client.
/// </para>
/// <para>
/// What a revocation actually reaches depends on how a token is validated. A refresh token is presented back
/// to this server on every use, so the next refresh fails. An access token that a resource server introspects
/// comes back inactive. An access token the resource server validates by itself, checking only the signature
/// and the expiry, never reaches this server at all and stays usable until it expires - which is what short
/// access-token lifetimes are for.
/// </para>
/// </remarks>
public interface ITokenRevoker
{
    /// <summary>
    /// Revokes every token issued to an end user before <paramref name="before"/>, across all their sessions.
    /// </summary>
    /// <param name="subject">The subject identifier the tokens carry.</param>
    /// <param name="before">The moment to revoke up to; the current time when omitted. Tokens issued at or
    /// after it are unaffected, so the user signing in again works with nothing to undo.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>A task that completes once the revocation is recorded.</returns>
    Task RevokeSubjectAsync(
        string subject, DateTimeOffset? before = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every token issued within one session before <paramref name="before"/>, leaving the same user's
    /// other sessions alone.
    /// </summary>
    /// <param name="sessionId">The session identifier the tokens carry.</param>
    /// <param name="before">The moment to revoke up to; the current time when omitted.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>A task that completes once the revocation is recorded.</returns>
    Task RevokeSessionAsync(
        string sessionId, DateTimeOffset? before = null, CancellationToken cancellationToken = default);
}
