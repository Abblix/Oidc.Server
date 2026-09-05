// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.E2E.TestHost.TestStubs;

/// <summary>
/// Test-host auth session stub: every request resolves to the same
/// predictable session, no consent / login UI involved. Lets E2E tests
/// drive the OIDC flow as a non-interactive RP without standing up an
/// authentication front-end.
/// </summary>
public sealed class AutoAuthSessionService(TimeProvider clock) : IAuthSessionService
{
    private readonly AuthSession _session = new(
        Subject: "e2e-subject",
        SessionId: "e2e-session",
        AuthenticationTime: clock.GetUtcNow(),
        IdentityProvider: "e2e-test");

    public async IAsyncEnumerable<AuthSession> GetAvailableAuthSessions()
    {
        yield return _session;
        await Task.CompletedTask;
    }

    public Task<AuthSession?> AuthenticateAsync() => Task.FromResult<AuthSession?>(_session);

    public Task SignInAsync(AuthSession authSession) => Task.CompletedTask;

    public Task SignOutAsync() => Task.CompletedTask;
}
