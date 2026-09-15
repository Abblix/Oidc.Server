// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.UserAuthentication;

public class AuthSessionTerminatingDecoratorTests
{
    private static readonly DateTimeOffset AuthenticatedAt = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

    private readonly List<string> _calls = [];
    private readonly Mock<IAuthSessionService> _inner = new(MockBehavior.Strict);
    private readonly Mock<IAuthSessionTerminator> _terminator = new(MockBehavior.Strict);

    public AuthSessionTerminatingDecoratorTests()
    {
        _terminator
            .Setup(t => t.TerminateAsync(It.IsAny<string>(), It.IsAny<string>()))
            .Callback((string sessionId, string subject) => _calls.Add($"terminate {sessionId} {subject}"))
            .ReturnsAsync((string sessionId, string subject) => new LogoutContext(sessionId, subject, "issuer"));
    }

    private AuthSessionTerminatingDecorator Decorator => new(_inner.Object, _terminator.Object);

    private static AuthSession Session(string subject, string sessionId) => new(
        subject, sessionId, AuthenticatedAt, "local");

    [Fact]
    public async Task Each_session_the_store_ended_is_terminated_after_the_store_wrote_the_new_one()
    {
        var signingIn = Session("carol", "carol-session");
        var written = new AuthSessionSignInResult(
            signingIn, [Session("alice", "alice-session"), Session("bob", "bob-session")]);
        _inner
            .Setup(s => s.SignInAsync(signingIn))
            .Callback(() => _calls.Add("write"))
            .ReturnsAsync(written);

        var result = await Decorator.SignInAsync(signingIn);

        Assert.Same(written, result);
        Assert.Equal(["write", "terminate alice-session alice", "terminate bob-session bob"], _calls);
    }

    [Fact]
    public async Task A_sign_in_ending_no_session_terminates_nothing()
    {
        var signingIn = Session("alice", "alice-session");
        _inner.Setup(s => s.SignInAsync(signingIn)).ReturnsAsync(new AuthSessionSignInResult(signingIn, []));

        await Decorator.SignInAsync(signingIn);

        Assert.Empty(_calls);
    }

    [Fact]
    public async Task A_sign_in_the_store_fails_terminates_nothing()
    {
        var signingIn = Session("alice", "alice-session");
        _inner.Setup(s => s.SignInAsync(signingIn)).ThrowsAsync(new InvalidOperationException("store refused"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => Decorator.SignInAsync(signingIn));

        Assert.Empty(_calls);
    }

    /// <summary>
    /// Logout ends the session itself, so signing out through the decorator must not end it a second time.
    /// </summary>
    [Fact]
    public async Task Signing_out_passes_through_without_terminating()
    {
        _inner.Setup(s => s.SignOutAsync()).Returns(Task.CompletedTask);

        await Decorator.SignOutAsync();

        _inner.Verify(s => s.SignOutAsync(), Times.Once);
        Assert.Empty(_calls);
    }

    [Fact]
    public async Task Reading_the_session_passes_through()
    {
        var current = Session("alice", "alice-session");
        _inner.Setup(s => s.AuthenticateAsync()).ReturnsAsync(current);
        _inner.Setup(s => s.GetAvailableAuthSessions()).Returns(new[] { current }.ToAsyncEnumerable());

        Assert.Same(current, await Decorator.AuthenticateAsync());
        Assert.Equal([current], await Decorator.GetAvailableAuthSessions().ToArrayAsync(TestContext.Current.CancellationToken));
    }
}
