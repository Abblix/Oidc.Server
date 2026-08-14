// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.MinimalApi.E2E.TestHost;

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
