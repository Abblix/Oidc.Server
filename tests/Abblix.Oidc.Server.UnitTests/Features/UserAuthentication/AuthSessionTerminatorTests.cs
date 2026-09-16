// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.UserAuthentication;

public class AuthSessionTerminatorTests
{
    private readonly List<string> _calls = [];
    private readonly Mock<ITokenRevoker> _tokenRevoker = new(MockBehavior.Strict);
    private readonly Mock<ISessionLogoutNotifier> _notifier = new(MockBehavior.Strict);
    private readonly OidcOptions _options = new();

    public AuthSessionTerminatorTests()
    {
        _tokenRevoker
            .Setup(r => r.RevokeSessionAsync(It.IsAny<string>(), null, It.IsAny<CancellationToken>()))
            .Callback((string sessionId, DateTimeOffset? _, CancellationToken _) => _calls.Add($"revoke {sessionId}"))
            .Returns(Task.CompletedTask);
        _notifier
            .Setup(n => n.NotifyClientsAsync(It.IsAny<string>(), It.IsAny<string>()))
            .Callback((string sessionId, string subject) => _calls.Add($"notify {sessionId} {subject}"))
            .ReturnsAsync((string sessionId, string subject) => new LogoutContext(sessionId, subject, "issuer"));
    }

    private AuthSessionTerminator Terminator => new(_tokenRevoker.Object, _notifier.Object, Options.Create(_options));

    [Fact]
    public async Task Revokes_the_session_tokens_before_any_client_is_told_when_the_deployment_asks()
    {
        _options.RevokeSessionTokensOnLogout = true;

        var context = await Terminator.TerminateAsync("session", "alice");

        Assert.Equal(["revoke session", "notify session alice"], _calls);
        Assert.Equal(("session", "alice"), (context.SessionId, context.SubjectId));
    }

    [Fact]
    public async Task Only_notifies_by_default()
    {
        await Terminator.TerminateAsync("session", "alice");

        Assert.Equal(["notify session alice"], _calls);
    }
}
