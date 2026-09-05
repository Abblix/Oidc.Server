// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// An auth session stub whose set of logged-in users a test can change between requests, standing in for a
/// browser where accounts are added and removed while the same host keeps running.
/// </summary>
/// <remarks>
/// One host is what makes this necessary rather than convenient. Signing keys are generated per host, so an
/// ID token minted by one host is unverifiable in the next, and a hint has to be an ID token this server
/// issued. Two sessions therefore cannot be arranged by standing up a second host: the same one has to hold
/// a single session long enough to mint the hint, and then hold two.
/// </remarks>
public sealed class MutableAuthSessionService(TimeProvider clock) : IAuthSessionService
{
    private AuthSession[] _sessions = [];

    /// <summary>
    /// Replaces the logged-in users, in the order the server will see them.
    /// </summary>
    public void SignedInAs(params string[] subjects) =>
        _sessions = [..subjects.Select(subject => new AuthSession(
            Subject: subject,
            SessionId: $"session-{subject}",
            AuthenticationTime: clock.GetUtcNow(),
            IdentityProvider: "e2e-test"))];

    public async IAsyncEnumerable<AuthSession> GetAvailableAuthSessions()
    {
        foreach (var session in _sessions)
            yield return session;

        await Task.CompletedTask;
    }

    /// <summary>
    /// The current session, which is the first one when several are signed in.
    /// </summary>
    /// <remarks>
    /// Only reached once a request has been narrowed to a single candidate, so which one it returns decides
    /// nothing the tests here measure - the endpoint refuses to choose before it gets this far.
    /// </remarks>
    public Task<AuthSession?> AuthenticateAsync() =>
        Task.FromResult(_sessions.Length > 0 ? _sessions[0] : null);

    public Task SignInAsync(AuthSession authSession) => Task.CompletedTask;

    public Task SignOutAsync()
    {
        _sessions = [];
        return Task.CompletedTask;
    }
}
