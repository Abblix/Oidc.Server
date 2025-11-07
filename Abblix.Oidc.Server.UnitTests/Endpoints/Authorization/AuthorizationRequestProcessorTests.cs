// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

/// <summary>
/// Unit tests for <see cref="AuthorizationRequestProcessor"/> verifying authorization
/// request processing logic per OAuth 2.0 and OIDC specifications.
/// </summary>
public class AuthorizationRequestProcessorTests
{
    private readonly Mock<IAuthSessionService> _authSessionService;
    private readonly Mock<IUserConsentsProvider> _consentsProvider;
    private readonly Mock<IAuthorizationCodeService> _authorizationCodeService;
    private readonly Mock<IAccessTokenService> _accessTokenService;
    private readonly Mock<IIdentityTokenService> _identityTokenService;
    private readonly Mock<TimeProvider> _timeProvider;
    private readonly AuthorizationRequestProcessor _processor;

    public AuthorizationRequestProcessorTests()
    {
        _authSessionService = new Mock<IAuthSessionService>(MockBehavior.Strict);
        _consentsProvider = new Mock<IUserConsentsProvider>(MockBehavior.Strict);
        _authorizationCodeService = new Mock<IAuthorizationCodeService>(MockBehavior.Strict);
        _accessTokenService = new Mock<IAccessTokenService>(MockBehavior.Strict);
        _identityTokenService = new Mock<IIdentityTokenService>(MockBehavior.Strict);
        _timeProvider = new Mock<TimeProvider>(MockBehavior.Strict);

        _processor = new AuthorizationRequestProcessor(
            _authSessionService.Object,
            _consentsProvider.Object,
            _authorizationCodeService.Object,
            _accessTokenService.Object,
            _identityTokenService.Object,
            _timeProvider.Object);
    }

    private static ValidAuthorizationRequest CreateRequest(
        string[]? responseType = null,
        string? prompt = null,
        TimeSpan? maxAge = null,
        string[]? acrValues = null,
        string[]? scope = null)
    {
        var authRequest = new AuthorizationRequest
        {
            ClientId = "client_123",
            ResponseType = responseType ?? new[] { ResponseTypes.Code },
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = scope ?? new[] { Scopes.OpenId },
            Prompt = prompt,
            MaxAge = maxAge,
            AcrValues = acrValues,
        };

        var clientInfo = new ClientInfo("client_123")
        {
            AuthorizationCodeExpiresIn = TimeSpan.FromMinutes(10),
        };

        return new ValidAuthorizationRequest(authRequest, clientInfo);
    }

    private AuthSession CreateAuthSession(
        string sessionId = "session_123",
        DateTimeOffset? authTime = null,
        string? acr = null)
    {
        return new AuthSession
        {
            SessionId = sessionId,
            Subject = "user_123",
            AuthenticationTime = authTime ?? DateTimeOffset.UtcNow,
            AuthContextClassRef = acr,
            AffectedClientIds = new List<string>(),
        };
    }

    private static UserConsents CreateConsents(
        ScopeDefinition[]? grantedScopes = null,
        ResourceDefinition[]? grantedResources = null,
        ScopeDefinition[]? pendingScopes = null,
        ResourceDefinition[]? pendingResources = null)
    {
        return new UserConsents
        {
            Granted = new ConsentDefinition
            {
                Scopes = grantedScopes ?? new[] { new ScopeDefinition(Scopes.OpenId) },
                Resources = grantedResources ?? Array.Empty<ResourceDefinition>(),
            },
            Pending = new ConsentDefinition
            {
                Scopes = pendingScopes ?? Array.Empty<ScopeDefinition>(),
                Resources = pendingResources ?? Array.Empty<ResourceDefinition>(),
            },
        };
    }

    /// <summary>
    /// Verifies login_required error when no sessions exist and prompt=none.
    /// Per OIDC, prompt=none forbids user interaction, so login cannot be prompted.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithNoSessionsAndPromptNone_ShouldReturnLoginRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: Prompts.None);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(AsyncEnumerable.Empty<AuthSession>());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.LoginRequired, error.Error);
        Assert.Contains("authentication", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies account_selection_required error when multiple sessions exist and prompt=none.
    /// Per OIDC, user cannot be prompted to select account when prompt=none.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithMultipleSessionsAndPromptNone_ShouldReturnAccountSelectionRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: Prompts.None);
        var sessions = new[] { CreateAuthSession("s1"), CreateAuthSession("s2") };

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(sessions.ToAsyncEnumerable());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.AccountSelectionRequired, error.Error);
        Assert.Contains("select a session", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
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
        Assert.Same(request.Model, loginRequired.Request);
    }

    /// <summary>
    /// Verifies LoginRequired response when prompt=login.
    /// Per OIDC, prompt=login forces reauthentication even with existing session.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPromptLogin_ShouldReturnLoginRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: Prompts.Login);
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
        Assert.Equal(3, accountSelection.AuthSessions.Length);
        Assert.Equal(sessions, accountSelection.AuthSessions);
    }

    /// <summary>
    /// Verifies AccountSelectionRequired when prompt=select_account.
    /// Per OIDC, prompt=select_account forces account selection even with single session.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPromptSelectAccount_ShouldReturnAccountSelectionRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: Prompts.SelectAccount);
        var session = CreateAuthSession();

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var accountSelection = Assert.IsType<AccountSelectionRequired>(result);
        Assert.Single(accountSelection.AuthSessions);
    }

    /// <summary>
    /// Verifies consent_required error when consent is pending and prompt=none.
    /// Per OIDC, user cannot be prompted for consent when prompt=none.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPendingConsentAndPromptNone_ShouldReturnConsentRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: Prompts.None);
        var session = CreateAuthSession();
        var consents = CreateConsents(pendingScopes: new[] { new ScopeDefinition("email") });

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.ConsentRequired, error.Error);
        Assert.Contains("consent", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies ConsentRequired when scopes pending consent.
    /// User must grant permission for requested scopes.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPendingScopes_ShouldReturnConsentRequired()
    {
        // Arrange
        var request = CreateRequest();
        var session = CreateAuthSession();
        var pendingScopes = new[] { new ScopeDefinition("email"), new ScopeDefinition("profile") };
        var consents = CreateConsents(pendingScopes: pendingScopes);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var consentRequired = Assert.IsType<ConsentRequired>(result);
        Assert.Equal(pendingScopes, consentRequired.Consent.Scopes);
    }

    /// <summary>
    /// Verifies ConsentRequired when resources pending consent.
    /// User must grant permission for requested resources.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPendingResources_ShouldReturnConsentRequired()
    {
        // Arrange
        var request = CreateRequest();
        var session = CreateAuthSession();
        var pendingResources = new[] { new ResourceDefinition(new Uri("https://api.example.com")) };
        var consents = CreateConsents(pendingResources: pendingResources);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var consentRequired = Assert.IsType<ConsentRequired>(result);
        Assert.Equal(pendingResources, consentRequired.Consent.Resources);
    }

    /// <summary>
    /// Verifies successful authorization with authorization code.
    /// Per OAuth 2.0, response_type=code generates authorization code.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeCode_ShouldGenerateAuthorizationCode()
    {
        // Arrange
        var request = CreateRequest(responseType: new[] { ResponseTypes.Code });
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var expectedCode = "auth_code_123";

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authSessionService
            .Setup(s => s.SignInAsync(session))
            .Returns(Task.CompletedTask);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync(expectedCode);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Equal(expectedCode, success.Code);
        Assert.Null(success.AccessToken);
        Assert.Null(success.IdToken);
    }

    /// <summary>
    /// Verifies successful authorization with access token.
    /// Per OAuth 2.0 Implicit Flow, response_type=token generates access token.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeToken_ShouldGenerateAccessToken()
    {
        // Arrange
        var request = CreateRequest(responseType: new[] { ResponseTypes.Token });
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var expectedToken = new EncodedJsonWebToken("access_token_jwt");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authSessionService
            .Setup(s => s.SignInAsync(session))
            .Returns(Task.CompletedTask);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(session, It.IsAny<AuthorizationContext>(), request.ClientInfo))
            .ReturnsAsync(expectedToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Null(success.Code);
        Assert.Same(expectedToken, success.AccessToken);
        Assert.Equal(TokenTypes.Bearer, success.TokenType);
        Assert.Null(success.IdToken);
    }

    /// <summary>
    /// Verifies successful authorization with ID token.
    /// Per OIDC Implicit Flow, response_type=id_token generates ID token.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeIdToken_ShouldGenerateIdToken()
    {
        // Arrange
        var request = CreateRequest(responseType: new[] { ResponseTypes.IdToken });
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var expectedIdToken = "id_token_jwt";

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authSessionService
            .Setup(s => s.SignInAsync(session))
            .Returns(Task.CompletedTask);

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                session,
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                true,
                null,
                null))
            .ReturnsAsync(expectedIdToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Null(success.Code);
        Assert.Null(success.AccessToken);
        Assert.Equal(expectedIdToken, success.IdToken);
    }

    /// <summary>
    /// Verifies hybrid flow with code and token.
    /// Per OIDC Hybrid Flow, response_type=code token generates both.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeCodeToken_ShouldGenerateBoth()
    {
        // Arrange
        var request = CreateRequest(responseType: new[] { ResponseTypes.Code, ResponseTypes.Token });
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var expectedCode = "auth_code_123";
        var expectedToken = new EncodedJsonWebToken("access_token_jwt");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authSessionService
            .Setup(s => s.SignInAsync(session))
            .Returns(Task.CompletedTask);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync(expectedCode);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(session, It.IsAny<AuthorizationContext>(), request.ClientInfo))
            .ReturnsAsync(expectedToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Equal(expectedCode, success.Code);
        Assert.Same(expectedToken, success.AccessToken);
        Assert.Equal(TokenTypes.Bearer, success.TokenType);
    }

    /// <summary>
    /// Verifies session filtering by max_age parameter.
    /// Per OIDC, sessions older than max_age must be excluded.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithMaxAge_ShouldFilterOldSessions()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var maxAge = TimeSpan.FromMinutes(30);
        var request = CreateRequest(maxAge: maxAge);

        var oldSession = CreateAuthSession("old", authTime: now - TimeSpan.FromHours(1));
        var recentSession = CreateAuthSession("recent", authTime: now - TimeSpan.FromMinutes(10));

        _timeProvider.Setup(t => t.GetUtcNow()).Returns(now);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { oldSession, recentSession }.ToAsyncEnumerable());

        // Act - should trigger LoginRequired because old session filtered out, leaving 1 recent session
        var consents = CreateConsents();

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, recentSession))
            .ReturnsAsync(consents);

        _authSessionService
            .Setup(s => s.SignInAsync(recentSession))
            .Returns(Task.CompletedTask);

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
        var request = CreateRequest(acrValues: new[] { "acr:high", "acr:medium" });

        var lowAcrSession = CreateAuthSession("low", acr: "acr:low");
        var highAcrSession = CreateAuthSession("high", acr: "acr:high");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { lowAcrSession, highAcrSession }.ToAsyncEnumerable());

        var consents = CreateConsents();

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, highAcrSession))
            .ReturnsAsync(consents);

        _authSessionService
            .Setup(s => s.SignInAsync(highAcrSession))
            .Returns(Task.CompletedTask);

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
    /// Verifies client is added to session's affected clients.
    /// Session must track all clients that have used it.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldAddClientToAffectedClients()
    {
        // Arrange
        var request = CreateRequest();
        var session = CreateAuthSession();
        var consents = CreateConsents();

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authSessionService
            .Setup(s => s.SignInAsync(session))
            .Returns(Task.CompletedTask);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        Assert.Contains(request.ClientInfo.ClientId, session.AffectedClientIds);
        _authSessionService.Verify(s => s.SignInAsync(session), Times.Once);
    }

    /// <summary>
    /// Verifies client not added twice to affected clients.
    /// If client already in list, SignInAsync should not be called.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithClientAlreadyInAffectedClients_ShouldNotSignInAgain()
    {
        // Arrange
        var request = CreateRequest();
        var session = CreateAuthSession();
        session.AffectedClientIds.Add(request.ClientInfo.ClientId); // Already present

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
        await _processor.ProcessAsync(request);

        // Assert
        _authSessionService.Verify(s => s.SignInAsync(It.IsAny<AuthSession>()), Times.Never);
    }

    /// <summary>
    /// Verifies authorization context contains correct data.
    /// Context should include granted scopes, resources, and request parameters.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldBuildCorrectAuthorizationContext()
    {
        // Arrange
        var nonce = "nonce_123";
        var codeChallenge = "challenge_123";
        var codeChallengeMethod = "S256";

        var authRequest = new AuthorizationRequest
        {
            ClientId = "client_123",
            ResponseType = new[] { ResponseTypes.Code },
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = new[] { Scopes.OpenId },
            Nonce = nonce,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
        };

        var clientInfo = new ClientInfo("client_123")
        {
            AuthorizationCodeExpiresIn = TimeSpan.FromMinutes(10),
        };

        var request = new ValidAuthorizationRequest(authRequest, clientInfo);
        var session = CreateAuthSession();

        var grantedScopes = new[] { new ScopeDefinition(Scopes.OpenId), new ScopeDefinition("email") };
        var grantedResources = new[] { new ResourceDefinition(new Uri("https://api.example.com")) };
        var consents = CreateConsents(grantedScopes: grantedScopes, grantedResources: grantedResources);

        AuthorizedGrant? capturedGrant = null;

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authSessionService
            .Setup(s => s.SignInAsync(session))
            .Returns(Task.CompletedTask);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .Callback<AuthorizedGrant, TimeSpan>((grant, _) => capturedGrant = grant)
            .ReturnsAsync("code");

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        Assert.NotNull(capturedGrant);
        var context = capturedGrant.AuthorizationContext;
        Assert.Equal("client_123", context.ClientId);
        Assert.Equal(grantedScopes, context.Scope);
        Assert.Equal(grantedResources, context.Resources);
        Assert.Equal(nonce, context.Nonce);
        Assert.Equal(codeChallenge, context.CodeChallenge);
        Assert.Equal(codeChallengeMethod, context.CodeChallengeMethod);
        Assert.Equal(request.Model.RedirectUri, context.RedirectUri);
    }
}
