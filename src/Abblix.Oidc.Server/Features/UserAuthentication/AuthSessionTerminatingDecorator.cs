// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.UserAuthentication;

/// <summary>
/// Ends, for their tokens and clients, the sessions a sign-in reports it ended.
/// </summary>
/// <remarks>
/// A host signs in through the registered <see cref="IAuthSessionService"/>, so decorating that registration
/// reaches those sign-ins whichever store keeps the sessions. The sessions are ended after the store has written
/// the new one, so a sign-in that fails signs nobody out.
/// </remarks>
/// <param name="inner">The store that keeps the sessions and decides which ones a sign-in ends.</param>
/// <param name="terminator">Ends each reported session.</param>
public class AuthSessionTerminatingDecorator(
    IAuthSessionService inner,
    IAuthSessionTerminator terminator) : IAuthSessionService
{
    /// <inheritdoc />
    public IAsyncEnumerable<AuthSession> GetAvailableAuthSessions() => inner.GetAvailableAuthSessions();

    /// <inheritdoc />
    public Task<AuthSession?> AuthenticateAsync() => inner.AuthenticateAsync();

    /// <inheritdoc />
    public async Task<AuthSessionSignInResult> SignInAsync(AuthSession authSession)
    {
        var result = await inner.SignInAsync(authSession);

        foreach (var endedSession in result.EndedSessions)
            await terminator.TerminateAsync(endedSession.SessionId, endedSession.Subject);

        return result;
    }

    /// <inheritdoc />
    public Task SignOutAsync() => inner.SignOutAsync();
}
