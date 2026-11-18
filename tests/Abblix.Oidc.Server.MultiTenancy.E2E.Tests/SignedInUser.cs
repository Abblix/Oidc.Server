// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// One user signed in to every request, so the authorization endpoint answers without a sign-in page.
/// </summary>
internal sealed class SignedInUser(TimeProvider clock) : IAuthSessionService
{
    private readonly AuthSession _session = new("alice", "session-1", clock.GetUtcNow(), "local");

    public async IAsyncEnumerable<AuthSession> GetAvailableAuthSessions()
    {
        yield return _session;
        await Task.CompletedTask;
    }

    public Task<AuthSession?> AuthenticateAsync() => Task.FromResult<AuthSession?>(_session);

    public Task<AuthSessionSignInResult> SignInAsync(AuthSession authSession)
        => Task.FromResult(new AuthSessionSignInResult(authSession, []));

    public Task SignOutAsync() => Task.CompletedTask;
}
