// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

public partial class AuthorizationRequestProcessorTests
{
    /// <summary>
    /// Verifies login_required error when no sessions exist and prompt=none.
    /// Per OIDC, prompt=none forbids user interaction, so login cannot be prompted.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithNoSessionsAndPromptNone_ShouldReturnLoginRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: [Prompts.None]);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(AsyncEnumerable.Empty<AuthSession>());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.LoginRequired, error.Error);
    }

    /// <summary>
    /// A hint naming one of several logged-in end users picks that one, instead of refusing the choice.
    /// </summary>
    /// <remarks>
    /// This is the case the parameter exists for. Ignore the hint and two sessions leave the server unable
    /// to choose, so it refuses with <c>account_selection_required</c> even though the request said which
    /// end user it meant.
    /// </remarks>
    [Fact]
    public async Task ProcessAsync_WithPromptNoneAndAHintNamingOneOfTwoSessions_UsesThatOne()
    {
        var request = CreateRequest(prompt: [Prompts.None], idTokenHintSubject: "user_2");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { Session("user_1"), Session("user_2") }.ToAsyncEnumerable());

        // Captured rather than asserted on the outcome. "Not an error" would hold equally if the server had
        // picked the other session, which is the failure this test exists for - so what it asserts is which
        // end user the request went on to be answered for.
        AuthSession? chosen = null;
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, It.IsAny<AuthSession>()))
            .Callback((ValidAuthorizationRequest _, AuthSession session) => chosen = session)
            .ReturnsAsync(new UserConsents
            {
                // Pending consent stops the flow right after the session was chosen, which is all this
                // test is about. Carrying on to a code would mean stubbing the rest of the pipeline to
                // measure something none of it decides.
                Pending = new ConsentDefinition([new ScopeDefinition(Scopes.OpenId)], []),
            });

        var result = await _processor.ProcessAsync(request);

        Assert.NotNull(chosen);
        Assert.Equal("user_2", chosen.Subject);

        // And the request got that far rather than being refused for want of a choice.
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.ConsentRequired, error.Error);
    }

    /// <summary>
    /// And a hint naming nobody who is logged in is refused rather than answered for somebody else.
    /// </summary>
    /// <remarks>
    /// OpenID Connect Core 1.0 Section 3.1.2.1: if the end user the ID Token identifies is not already
    /// logged in and is not logged in as a result of the request, the server "MUST return an error, such as
    /// login_required". Ignore the hint and this request is answered instead - and with one of the two
    /// sessions revoked, answered silently for the account the client never asked about.
    /// </remarks>
    [Fact]
    public async Task ProcessAsync_WithPromptNoneAndAHintNamingNobodyLoggedIn_ShouldReturnLoginRequired()
    {
        var request = CreateRequest(prompt: [Prompts.None], idTokenHintSubject: "somebody-else");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { Session("user_1"), Session("user_2") }.ToAsyncEnumerable());

        var result = await _processor.ProcessAsync(request);

        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.LoginRequired, error.Error);
    }

    /// <summary>
    /// Without a hint the same two sessions still refuse, which is what says
    /// <see cref="ProcessAsync_WithPromptNoneAndAHintNamingOneOfTwoSessions_UsesThatOne"/> and
    /// <see cref="ProcessAsync_WithPromptNoneAndAHintNamingNobodyLoggedIn_ShouldReturnLoginRequired"/> measure the
    /// hint and not some other change to how sessions are counted.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPromptNoneAndNoHint_StillRefusesToChoose()
    {
        var request = CreateRequest(prompt: [Prompts.None]);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { Session("user_1"), Session("user_2") }.ToAsyncEnumerable());

        var result = await _processor.ProcessAsync(request);

        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.AccountSelectionRequired, error.Error);
    }

    /// <summary>
    /// A hint differing from a logged-in subject only in case names somebody else.
    /// </summary>
    /// <remarks>
    /// A subject is an opaque identifier, compared octet for octet, and a host is free to mint two that
    /// differ only in case. Nothing else in this suite visits the distinction, so relaxing the comparison to
    /// ignore case would otherwise leave every test green.
    /// </remarks>
    [Fact]
    public async Task ProcessAsync_WithAHintDifferingOnlyInCase_ShouldReturnLoginRequired()
    {
        var request = CreateRequest(prompt: [Prompts.None], idTokenHintSubject: "USER_1");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { Session("user_1") }.ToAsyncEnumerable());

        var result = await _processor.ProcessAsync(request);

        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.LoginRequired, error.Error);
    }

    private static AuthSession Session(string subject)
        => new(subject, $"session-of-{subject}", TimeProvider.System.GetUtcNow(), "local");

    /// <summary>
    /// Initiating User Registration via OpenID Connect 1.0: prompt=create yields the registration signal
    /// even when no session exists. Without its own arm the value falls through to the generic no-session
    /// branch and the host sees an ordinary login request, losing the registration intent.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPromptCreate_NoSessions_ShouldReturnRegistrationRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: [Prompts.Create]);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(AsyncEnumerable.Empty<AuthSession>());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.IsType<RegistrationRequired>(result);
    }

    /// <summary>
    /// Initiating User Registration via OpenID Connect 1.0: the registration experience is shown
    /// regardless of whether the user is currently logged in - an existing session must not make
    /// the request proceed as a normal authentication.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPromptCreate_ExistingSession_ShouldReturnRegistrationRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: [Prompts.Create]);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { CreateAuthSession() }.ToAsyncEnumerable());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.IsType<RegistrationRequired>(result);
    }

    /// <summary>
    /// Verifies that when the request omits max_age, the client's registered default_max_age is
    /// applied (OIDC Core section 2 / section 3.1.2.1): a session older than default_max_age is filtered out.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithoutMaxAge_AppliesClientDefaultMaxAge()
    {
        // Arrange - request has no max_age; the client registered default_max_age = 5 minutes.
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        _timeProvider.SetUtcNow(now);
        var request = CreateRequest(prompt: [Prompts.None], defaultMaxAge: TimeSpan.FromMinutes(5));
        var staleSession = CreateAuthSession("stale", authTime: now - TimeSpan.FromHours(1));

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { staleSession }.ToAsyncEnumerable());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert - the stale session is filtered by the default_max_age fallback, leaving none.
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.LoginRequired, error.Error);
    }

    /// <summary>
    /// Verifies that when the request omits acr_values, the client's registered default_acr_values
    /// is applied (OIDC Core section 2): a session whose ACR is not among them is filtered out.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithoutAcrValues_AppliesClientDefaultAcrValues()
    {
        // Arrange - request has no acr_values; the client registered default_acr_values = ["high"].
        var request = CreateRequest(prompt: [Prompts.None], defaultAcrValues: ["high"]);
        var session = CreateAuthSession("s1", acr: "low");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert - the session's ACR does not match the default, so it is filtered, leaving none.
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.LoginRequired, error.Error);
    }

    /// <summary>
    /// Verifies account_selection_required error when multiple sessions exist and prompt=none.
    /// Per OIDC, user cannot be prompted to select account when prompt=none.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithMultipleSessionsAndPromptNone_ShouldReturnAccountSelectionRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: [Prompts.None]);
        var sessions = new[] { CreateAuthSession("s1"), CreateAuthSession("s2") };

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(sessions.ToAsyncEnumerable());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.AccountSelectionRequired, error.Error);
    }

    /// <summary>
    /// Verifies LoginRequired response when no sessions exist.
    /// Per OIDC, user must authenticate when no valid session exists.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithNoSessions_ShouldReturnLoginRequired()
    {
        // Arrange
        var request = CreateRequest();

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(AsyncEnumerable.Empty<AuthSession>());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var loginRequired = Assert.IsType<LoginRequired>(result);
        Assert.Same(request.Model, loginRequired.Model);
    }

    /// <summary>
    /// Verifies LoginRequired response when prompt=login.
    /// Per OIDC, prompt=login forces reauthentication even with existing session.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPromptLogin_ShouldReturnLoginRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: [Prompts.Login]);
        var session = CreateAuthSession();

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.IsType<LoginRequired>(result);
    }

    /// <summary>
    /// Sending the end user to log in or to create an account stamps the request with the moment it did, so the
    /// request coming back from that page can tell a session opened for it from one that was already there.
    /// </summary>
    [Theory]
    [InlineData(Prompts.Login)]
    [InlineData(Prompts.Create)]
    public async Task PromptLoginOrCreate_StampsRequestWhenSendingEndUser(string prompt)
    {
        var request = CreateRequest(prompt: [prompt]);
        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { CreateAuthSession() }.ToAsyncEnumerable());

        var result = await _processor.ProcessAsync(request);

        Assert.Equal(_timeProvider.GetUtcNow(), result.Model.PromptedAt);
    }

    /// <summary>
    /// A request coming back from the login or account-creation page with a session opened after the server sent
    /// the end user there proceeds with that session instead of sending the end user there again.
    /// </summary>
    [Theory]
    [InlineData(Prompts.Login)]
    [InlineData(Prompts.Create)]
    public async Task PromptLoginOrCreate_WithSessionOpenedSincePrompted_Proceeds(string prompt)
    {
        var promptedAt = _timeProvider.GetUtcNow();
        _timeProvider.Advance(TimeSpan.FromMinutes(1));
        var session = CreateAuthSession(authTime: _timeProvider.GetUtcNow());
        var request = CreateRequest(prompt: [prompt], promptedAt: promptedAt);
        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(CreateConsents());
        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        var result = await _processor.ProcessAsync(request);

        Assert.IsType<SuccessfullyAuthenticated>(result);
    }

    /// <summary>
    /// Of two sessions, the one opened since the end user was sent away is the one the request proceeds with,
    /// rather than the end user being asked to choose between it and one opened before.
    /// </summary>
    [Fact]
    public async Task PromptLogin_WithSessionsOpenedBeforeAndSince_ProceedsWithSessionSince()
    {
        var before = CreateAuthSession(sessionId: "before", authTime: _timeProvider.GetUtcNow());
        _timeProvider.Advance(TimeSpan.FromMinutes(1));
        var promptedAt = _timeProvider.GetUtcNow();
        _timeProvider.Advance(TimeSpan.FromMinutes(1));
        var since = CreateAuthSession(sessionId: "since", authTime: _timeProvider.GetUtcNow());
        var request = CreateRequest(prompt: [Prompts.Login], promptedAt: promptedAt);
        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { before, since }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, since))
            .ReturnsAsync(CreateConsents());
        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        var result = await _processor.ProcessAsync(request);

        Assert.Equal(since.SessionId, Assert.IsType<SuccessfullyAuthenticated>(result).SessionId);
    }

    /// <summary>
    /// A session opened in the same second the end user was sent away counts as opened for the request: the
    /// moment a session was authenticated is kept to the second, so a finer comparison would send back an end
    /// user who logged in at once.
    /// </summary>
    [Fact]
    public async Task PromptLogin_WithSessionOpenedInSameSecond_Proceeds()
    {
        var second = DateTimeOffset.FromUnixTimeSeconds(_timeProvider.GetUtcNow().ToUnixTimeSeconds());
        var session = CreateAuthSession(authTime: second);
        var request = CreateRequest(prompt: [Prompts.Login], promptedAt: second.AddMilliseconds(500));
        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(CreateConsents());
        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        var result = await _processor.ProcessAsync(request);

        Assert.IsType<SuccessfullyAuthenticated>(result);
    }

    /// <summary>
    /// A request coming back with only a session opened before the server sent the end user away still asks for
    /// login or account creation: that session is not the one the client asked for.
    /// </summary>
    [Theory]
    [InlineData(Prompts.Login, typeof(LoginRequired))]
    [InlineData(Prompts.Create, typeof(RegistrationRequired))]
    public async Task PromptLoginOrCreate_WithOnlySessionOpenedBefore_AsksAgain(string prompt, Type expected)
    {
        var session = CreateAuthSession(authTime: _timeProvider.GetUtcNow());
        _timeProvider.Advance(TimeSpan.FromMinutes(1));
        var request = CreateRequest(prompt: [prompt], promptedAt: _timeProvider.GetUtcNow());
        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        var result = await _processor.ProcessAsync(request);

        Assert.IsType(expected, result);
    }

    /// <summary>
    /// Verifies AccountSelectionRequired when multiple sessions exist.
    /// User must select which session to use for authorization.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithMultipleSessions_ShouldReturnAccountSelectionRequired()
    {
        // Arrange
        var request = CreateRequest();
        var sessions = new[] { CreateAuthSession("s1"), CreateAuthSession("s2"), CreateAuthSession("s3") };

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(sessions.ToAsyncEnumerable());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var accountSelection = Assert.IsType<AccountSelectionRequired>(result);
        Assert.Equal(3, accountSelection.Users.Length);
        Assert.Equal(sessions, accountSelection.Users);
    }

    /// <summary>
    /// Verifies AccountSelectionRequired when prompt=select_account.
    /// Per OIDC, prompt=select_account forces account selection even with single session.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPromptSelectAccount_ShouldReturnAccountSelectionRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: [Prompts.SelectAccount]);
        var session = CreateAuthSession();

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var accountSelection = Assert.IsType<AccountSelectionRequired>(result);
        Assert.Single(accountSelection.Users);
    }

    /// <summary>
    /// Verifies session filtering by max_age parameter.
    /// Per OIDC, sessions older than max_age must be excluded.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithMaxAge_ShouldFilterOldSessions()
    {
        // Arrange
        var now = _timeProvider.GetUtcNow();
        var maxAge = TimeSpan.FromMinutes(30);
        var request = CreateRequest(maxAge: maxAge);

        var oldSession = CreateAuthSession("old", authTime: now - TimeSpan.FromHours(1));
        var recentSession = CreateAuthSession("recent", authTime: now - TimeSpan.FromMinutes(10));

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { oldSession, recentSession }.ToAsyncEnumerable());

        // Act - should trigger LoginRequired because old session filtered out, leaving 1 recent session
        var consents = CreateConsents();

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, recentSession))
            .ReturnsAsync(consents);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        var result = await _processor.ProcessAsync(request);

        // Assert - recent session should be used
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.NotNull(success.Code);
    }

    /// <summary>
    /// Verifies session filtering by ACR values.
    /// Per OIDC, only sessions matching requested ACR values should be used.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithAcrValues_ShouldFilterByAcr()
    {
        // Arrange
        var request = CreateRequest(acrValues: ["acr:high", "acr:medium"]);

        var lowAcrSession = CreateAuthSession("low", acr: "acr:low");
        var highAcrSession = CreateAuthSession("high", acr: "acr:high");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { lowAcrSession, highAcrSession }.ToAsyncEnumerable());

        var consents = CreateConsents();

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, highAcrSession))
            .ReturnsAsync(consents);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert - high ACR session should be used
        Assert.IsType<SuccessfullyAuthenticated>(result);
        _consentsProvider.Verify(p => p.GetUserConsentsAsync(request, highAcrSession), Times.Once);
    }

    /// <summary>
    /// Verifies prompt=none with single valid session succeeds.
    /// When prompt=none and exactly one session exists with all consents granted, authorization succeeds.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPromptNoneAndSingleSession_ShouldSucceed()
    {
        // Arrange
        var request = CreateRequest(prompt: [Prompts.None]);
        var session = CreateAuthSession();
        var consents = CreateConsents();

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.IsType<SuccessfullyAuthenticated>(result);
    }

    /// <summary>
    /// Verifies max_age parameter filters all sessions when all are too old.
    /// When max_age excludes all sessions, LoginRequired should be returned.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithMaxAgeExcludingAllSessions_ShouldReturnLoginRequired()
    {
        // Arrange
        var now = _timeProvider.GetUtcNow();
        var maxAge = TimeSpan.FromMinutes(30);
        var request = CreateRequest(maxAge: maxAge);

        var oldSession1 = CreateAuthSession("old1", authTime: now - TimeSpan.FromHours(2));
        var oldSession2 = CreateAuthSession("old2", authTime: now - TimeSpan.FromHours(1));

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { oldSession1, oldSession2 }.ToAsyncEnumerable());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.IsType<LoginRequired>(result);
    }

    /// <summary>
    /// Verifies ACR filtering excludes all sessions when none match.
    /// When requested ACR values don't match any session, LoginRequired should be returned.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithAcrValuesExcludingAllSessions_ShouldReturnLoginRequired()
    {
        // Arrange
        var request = CreateRequest(acrValues: ["acr:high", "acr:medium"]);

        var lowAcrSession1 = CreateAuthSession("low1", acr: "acr:low");
        var lowAcrSession2 = CreateAuthSession("low2", acr: "acr:basic");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { lowAcrSession1, lowAcrSession2 }.ToAsyncEnumerable());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.IsType<LoginRequired>(result);
    }
}
