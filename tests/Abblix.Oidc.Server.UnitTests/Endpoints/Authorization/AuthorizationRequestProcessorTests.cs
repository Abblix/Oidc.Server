// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.ResponseObject;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.ImplicitFlow;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Abblix.Oidc.Server.Features.ReusePrevention;
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
    private readonly Mock<IRevocationCutoffChecker> _cutoffChecker = new();
    private readonly Mock<IAuthorizationCodeService> _authorizationCodeService;
    private readonly Mock<IAccessTokenService> _accessTokenService;
    private readonly Mock<IIdentityTokenService> _identityTokenService;
    private readonly Mock<IAuthorizationDetailsPolicy> _authorizationDetailsPolicy;
    private readonly FakeTimeProvider _timeProvider;
    private readonly AuthorizationRequestProcessor _processor;

    public AuthorizationRequestProcessorTests()
    {
        _authSessionService = new Mock<IAuthSessionService>(MockBehavior.Strict);
        _consentsProvider = new Mock<IUserConsentsProvider>(MockBehavior.Strict);
        _authorizationCodeService = new Mock<IAuthorizationCodeService>(MockBehavior.Strict);
        _accessTokenService = new Mock<IAccessTokenService>(MockBehavior.Strict);
        _identityTokenService = new Mock<IIdentityTokenService>(MockBehavior.Strict);
        _authorizationDetailsPolicy = new Mock<IAuthorizationDetailsPolicy>(MockBehavior.Strict);

        // The processor reaches the policy only through the backstop, which asks the GRANTED-phase
        // question (RFC 9396 section 7.1). For these tests the granted set is already a valid
        // narrowing, so the policy passes it through unchanged; escalation and failure cases are
        // covered in ConsentConstraintEnforcerTests against the real enforcer.
        _authorizationDetailsPolicy
            .Setup(p => p.ApplyGrantedAsync(
                It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((JsonArray? ad, ClientInfo _, CancellationToken _) => ad);

        _timeProvider = new FakeTimeProvider();

        // No cutoff recorded is the ordinary case; the tests about revocation build their own.
        _cutoffChecker
            .Setup(c => c.IsSessionRefusedAsync(It.IsAny<AuthSession>()))
            .ReturnsAsync(false);

        // A real ConsentConstraintEnforcer (not a mock) so the anti-escalation backstop is
        // exercised end-to-end through the processor - granted scopes/resources that exceed the
        // request must throw before the grant is built.
        _processor = new AuthorizationRequestProcessor(
            _authSessionService.Object,
            _consentsProvider.Object,
            _cutoffChecker.Object,
            new SubjectTypeConverter(),
            _timeProvider,
            [
                new AuthorizationCodeBuilder(_authorizationCodeService.Object, Mock.Of<IAuthorizationValueReuseDetector>()),
                new TokenResponseBuilder(_accessTokenService.Object),
                new IdTokenResponseBuilder(_identityTokenService.Object),
            ],
            new ConsentConstraintEnforcer(_authorizationDetailsPolicy.Object));
    }

    private static ValidAuthorizationRequest CreateRequest(
        string[]? responseType = null,
        string? prompt = null,
        TimeSpan? maxAge = null,
        string[]? acrValues = null,
        string[]? scope = null,
        JsonArray? authorizationDetails = null,
        TimeSpan? defaultMaxAge = null,
        string[]? defaultAcrValues = null,
        string? idTokenHintSubject = null)
    {
        var authRequest = new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = responseType ?? [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            Scope = scope ?? [Scopes.OpenId],
            Prompt = prompt,
            MaxAge = maxAge,
            AcrValues = acrValues,
            AuthorizationDetails = authorizationDetails,
        };

        var clientInfo = new ClientInfo(TestConstants.DefaultClientId)
        {
            AuthorizationCodeExpiresIn = TimeSpan.FromMinutes(10),
            DefaultMaxAge = defaultMaxAge,
            DefaultAcrValues = defaultAcrValues,
        };

        var context = new AuthorizationValidationContext(authRequest)
        {
            ClientInfo = clientInfo,
            ResponseMode = ResponseModes.Query,
            Scope = scope?.Select(s => new ScopeDefinition(s)).ToArray() ?? [new ScopeDefinition(Scopes.OpenId)],
            Resources = [],
            AuthorizationDetails = authorizationDetails,
            IdTokenHintSubject = idTokenHintSubject,
        };

        return new ValidAuthorizationRequest(context);
    }

    private static AuthSession CreateAuthSession(
        string sessionId = "session_123",
        DateTimeOffset? authTime = null,
        string? acr = null)
    {
        return new AuthSession(
            Subject: "user_123",
            SessionId: sessionId,
            AuthenticationTime: authTime ?? DateTimeOffset.UtcNow,
            IdentityProvider: "local")
        {
            AuthContextClassRef = acr,
            // AffectedClientIds is left at its default on purpose: hard-coding a List here would test the
            // fixture's collection rather than the one a session actually carries.
        };
    }

    private static UserConsents CreateConsents(
        ScopeDefinition[]? grantedScopes = null,
        ResourceDefinition[]? grantedResources = null,
        ScopeDefinition[]? pendingScopes = null,
        ResourceDefinition[]? pendingResources = null,
        JsonArray? grantedAuthorizationDetails = null,
        JsonArray? pendingAuthorizationDetails = null)
    {
        return new UserConsents
        {
            Granted = new ConsentDefinition(
                Scopes: grantedScopes ?? [new ScopeDefinition(Scopes.OpenId)],
                Resources: grantedResources ?? [])
            {
                AuthorizationDetails = grantedAuthorizationDetails,
            },
            Pending = new ConsentDefinition(
                Scopes: pendingScopes ?? [],
                Resources: pendingResources ?? [])
            {
                AuthorizationDetails = pendingAuthorizationDetails,
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
        var request = CreateRequest(prompt: Prompts.None, idTokenHintSubject: "user_2");

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
        var request = CreateRequest(prompt: Prompts.None, idTokenHintSubject: "somebody-else");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { Session("user_1"), Session("user_2") }.ToAsyncEnumerable());

        var result = await _processor.ProcessAsync(request);

        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.LoginRequired, error.Error);
    }

    /// <summary>
    /// Without a hint the same two sessions still refuse, which is what says the tests above measure the
    /// hint and not some other change to how sessions are counted.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPromptNoneAndNoHint_StillRefusesToChoose()
    {
        var request = CreateRequest(prompt: Prompts.None);

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
        var request = CreateRequest(prompt: Prompts.None, idTokenHintSubject: "USER_1");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { Session("user_1") }.ToAsyncEnumerable());

        var result = await _processor.ProcessAsync(request);

        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.LoginRequired, error.Error);
    }

    private static AuthSession Session(string subject)
        => new(subject, $"session-of-{subject}", DateTimeOffset.UtcNow, "local");

    /// <summary>
    /// Initiating User Registration via OpenID Connect 1.0: prompt=create yields the registration signal
    /// even when no session exists. Without its own arm the value falls through to the generic no-session
    /// branch and the host sees an ordinary login request, losing the registration intent.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPromptCreate_NoSessions_ShouldReturnRegistrationRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: Prompts.Create);

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
        var request = CreateRequest(prompt: Prompts.Create);

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
    /// applied (OIDC Core §2 / §3.1.2.1): a session older than default_max_age is filtered out.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithoutMaxAge_AppliesClientDefaultMaxAge()
    {
        // Arrange - request has no max_age; the client registered default_max_age = 5 minutes.
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        _timeProvider.SetUtcNow(now);
        var request = CreateRequest(prompt: Prompts.None, defaultMaxAge: TimeSpan.FromMinutes(5));
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
    /// is applied (OIDC Core §2): a session whose ACR is not among them is filtered out.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithoutAcrValues_AppliesClientDefaultAcrValues()
    {
        // Arrange - request has no acr_values; the client registered default_acr_values = ["high"].
        var request = CreateRequest(prompt: Prompts.None, defaultAcrValues: ["high"]);
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
        var request = CreateRequest(prompt: Prompts.SelectAccount);
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
    /// Verifies consent_required error when consent is pending and prompt=none.
    /// Per OIDC, user cannot be prompted for consent when prompt=none.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPendingConsentAndPromptNone_ShouldReturnConsentRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: Prompts.None);
        var session = CreateAuthSession();
        var consents = CreateConsents(pendingScopes: [new ScopeDefinition("email")]);

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
        Assert.Equal(pendingScopes, consentRequired.RequiredUserConsents.Scopes);
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
        Assert.Equal(pendingResources, consentRequired.RequiredUserConsents.Resources);
    }

    /// <summary>
    /// Verifies successful authorization with authorization code.
    /// Per OAuth 2.0, response_type=code generates authorization code.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeCode_ShouldGenerateAuthorizationCode()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Code]);
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
    /// Anti-escalation backstop (#185): the IUserConsentsProvider contract permits a narrower grant
    /// than the request, never a broader one. A granted scope absent from the request is a host-side
    /// contract violation and must fail loud with an exception instead of issuing an escalated grant.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_GrantedScopeExceedsRequest_ShouldThrow()
    {
        // Arrange - request carries only openid; the consent provider returns an extra "admin"
        // scope that was never requested (e.g. browser tampering it failed to intersect away).
        var request = CreateRequest(responseType: [ResponseTypes.Code], scope: [Scopes.OpenId]);
        var session = CreateAuthSession();
        var consents = CreateConsents(
            grantedScopes: [new ScopeDefinition(Scopes.OpenId), new ScopeDefinition("admin")]);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);
        _authSessionService.Setup(s => s.SignInAsync(session)).Returns(Task.CompletedTask);
        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(), request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        // Act + Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() => _processor.ProcessAsync(request));
    }

    /// <summary>
    /// Anti-escalation backstop (#185): a granted resource absent from the request is likewise a
    /// host-side contract violation and must fail loud.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_GrantedResourceNotRequested_ShouldThrow()
    {
        // Arrange - the request carries no resources; the provider grants one anyway.
        var request = CreateRequest(responseType: [ResponseTypes.Code]);
        var session = CreateAuthSession();
        var consents = CreateConsents(
            grantedResources: [new ResourceDefinition(new Uri("https://api.example/admin"))]);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);
        _authSessionService.Setup(s => s.SignInAsync(session)).Returns(Task.CompletedTask);
        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(), request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        // Act + Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() => _processor.ProcessAsync(request));
    }

    /// <summary>
    /// Verifies successful authorization with access token.
    /// Per OAuth 2.0 Implicit Flow, response_type=token generates access token.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeToken_ShouldGenerateAccessToken()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Token]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var jwt = new JsonWebToken();
        var expectedToken = new EncodedJsonWebToken(jwt, "access_token_jwt");

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
    /// RFC 6749 §3.3 / §4.2.2: when the consent decision narrows the grant, the front-channel
    /// <c>scope</c> parameter of an implicit/hybrid response must advertise the GRANTED scope
    /// (matching the issued access token), not the broader requested set. Drives the real processor and
    /// the real <see cref="AuthorizationResponseEncoder"/> end to end.
    /// </summary>
    [Fact]
    public async Task ProcessAndEncode_ImplicitFlowWithNarrowedConsent_EmitsGrantedScopeNotRequested()
    {
        // Arrange - request asks for openid profile email; the consent provider grants only openid profile.
        var request = CreateRequest(
            responseType: [ResponseTypes.Token],
            scope: [Scopes.OpenId, Scopes.Profile, Scopes.Email]);
        var session = CreateAuthSession();
        var consents = CreateConsents(
            grantedScopes: [new ScopeDefinition(Scopes.OpenId), new ScopeDefinition(Scopes.Profile)]);

        var accessToken = new EncodedJsonWebToken(new JsonWebToken(), "access_token_jwt");

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
            .ReturnsAsync(accessToken);

        var response = await _processor.ProcessAsync(request);

        // Encode through the real response encoder. Query (non-JARM) mode means no response JWT is built,
        // so the JWT builder is never invoked; iss advertising is disabled to keep the issuer provider idle.
        var metadata = new Mock<IAuthorizationMetadataProvider>(MockBehavior.Strict);
        metadata.SetupGet(m => m.AuthorizationResponseIssParameterSupported).Returns(false);
        var encoder = new AuthorizationResponseEncoder(
            new Mock<IIssuerProvider>(MockBehavior.Strict).Object,
            metadata.Object,
            new Mock<IResponseJwtBuilder>(MockBehavior.Strict).Object);

        // Act
        await encoder.EncodeAsync(response);

        // Assert - the front-channel scope reflects the granted set, not the requested set.
        var success = Assert.IsType<SuccessfullyAuthenticated>(response);
        Assert.Equal($"{Scopes.OpenId} {Scopes.Profile}", success.Scope);
    }

    /// <summary>
    /// Verifies successful authorization with ID token.
    /// Per OIDC Implicit Flow, response_type=id_token generates ID token.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeIdToken_ShouldGenerateIdToken()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.IdToken]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var jwt = new JsonWebToken();
        var expectedIdToken = new EncodedJsonWebToken(jwt, "id_token_jwt");

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
        Assert.Same(expectedIdToken, success.IdToken);
    }

    /// <summary>
    /// Verifies hybrid flow with code and token.
    /// Per OIDC Hybrid Flow, response_type=code token generates both.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeCodeToken_ShouldGenerateBoth()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Code, ResponseTypes.Token]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var expectedCode = "auth_code_123";
        var jwt = new JsonWebToken();
        var expectedToken = new EncodedJsonWebToken(jwt, "access_token_jwt");

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
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            Scope = [Scopes.OpenId, "email"],
            Nonce = nonce,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
        };

        var clientInfo = new ClientInfo(TestConstants.DefaultClientId)
        {
            AuthorizationCodeExpiresIn = TimeSpan.FromMinutes(10),
        };

        var grantedScopes = new[] { new ScopeDefinition(Scopes.OpenId), new ScopeDefinition("email") };
        var grantedResources = new[] { new ResourceDefinition(new Uri("https://api.example.com")) };

        var context = new AuthorizationValidationContext(authRequest)
        {
            ClientInfo = clientInfo,
            ResponseMode = ResponseModes.Query,
            Scope = grantedScopes,
            Resources = grantedResources,
        };

        var request = new ValidAuthorizationRequest(context);
        var session = CreateAuthSession();

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
        var authContext = capturedGrant.Context;
        Assert.Equal(TestConstants.DefaultClientId, authContext.ClientId);
        Assert.Equal(grantedScopes.Select(s => s.Scope).ToArray(), authContext.Scope);
        Assert.Equal(grantedResources.Select(r => r.Resource).ToArray(), authContext.Resources);
        Assert.Equal(nonce, authContext.Nonce);
        Assert.Equal(codeChallenge, authContext.CodeChallenge);
        Assert.Equal(codeChallengeMethod, authContext.CodeChallengeMethod);
        Assert.Equal(request.Model.RedirectUri, authContext.RedirectUri);
    }

    /// <summary>
    /// Verifies hybrid flow with code and id_token.
    /// Per OIDC Hybrid Flow, response_type=code id_token generates both.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeCodeIdToken_ShouldGenerateBoth()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Code, ResponseTypes.IdToken]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var expectedCode = "auth_code_123";
        var jwt = new JsonWebToken();
        var expectedIdToken = new EncodedJsonWebToken(jwt, "id_token_jwt");

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

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                session,
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                false,
                expectedCode,
                null))
            .ReturnsAsync(expectedIdToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Equal(expectedCode, success.Code);
        Assert.Null(success.AccessToken);
        Assert.Same(expectedIdToken, success.IdToken);
    }

    /// <summary>
    /// Verifies hybrid flow with token and id_token.
    /// Per OIDC Hybrid Flow, response_type=token id_token generates both.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeTokenIdToken_ShouldGenerateBoth()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Token, ResponseTypes.IdToken]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var accessJwt = new JsonWebToken();
        var expectedToken = new EncodedJsonWebToken(accessJwt, "access_token_jwt");
        var idJwt = new JsonWebToken();
        var expectedIdToken = new EncodedJsonWebToken(idJwt, "id_token_jwt");

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

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                session,
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                false,
                null,
                expectedToken.EncodedJwt))
            .ReturnsAsync(expectedIdToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Null(success.Code);
        Assert.Same(expectedToken, success.AccessToken);
        Assert.Equal(TokenTypes.Bearer, success.TokenType);
        Assert.Same(expectedIdToken, success.IdToken);
    }

    /// <summary>
    /// Verifies hybrid flow with all three response types.
    /// Per OIDC Hybrid Flow, response_type=code token id_token generates all three.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeCodeTokenIdToken_ShouldGenerateAll()
    {
        // Arrange
        var request = CreateRequest(
            responseType: [ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var expectedCode = "auth_code_123";
        var accessJwt = new JsonWebToken();
        var expectedToken = new EncodedJsonWebToken(accessJwt, "access_token_jwt");
        var idJwt = new JsonWebToken();
        var expectedIdToken = new EncodedJsonWebToken(idJwt, "id_token_jwt");

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

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                session,
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                false,
                expectedCode,
                expectedToken.EncodedJwt))
            .ReturnsAsync(expectedIdToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Equal(expectedCode, success.Code);
        Assert.Same(expectedToken, success.AccessToken);
        Assert.Equal(TokenTypes.Bearer, success.TokenType);
        Assert.Same(expectedIdToken, success.IdToken);
    }

    /// <summary>
    /// Verifies successful authorization with all session data passed to tokens.
    /// Session details should be included in authorization grant.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldPassSessionToTokenServices()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Code]);
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
                It.Is<AuthorizedGrant>(g => g.AuthSession == session),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        _authorizationCodeService.Verify(
            s => s.GenerateAuthorizationCodeAsync(
                It.Is<AuthorizedGrant>(g => g.AuthSession == session),
                request.ClientInfo.AuthorizationCodeExpiresIn),
            Times.Once);
    }

    /// <summary>
    /// Verifies prompt=none with single valid session succeeds.
    /// When prompt=none and exactly one session exists with all consents granted, authorization succeeds.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPromptNoneAndSingleSession_ShouldSucceed()
    {
        // Arrange
        var request = CreateRequest(prompt: Prompts.None);
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

    /// <summary>
    /// Verifies successful authorization includes session ID in result.
    /// Session ID should be preserved in the authentication result.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldIncludeSessionIdInResult()
    {
        // Arrange
        var sessionId = "test_session_id_123";
        var request = CreateRequest();
        var session = CreateAuthSession(sessionId: sessionId);
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
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Equal(sessionId, success.SessionId);
    }

    /// <summary>
    /// Verifies ID token generation when it's the only response type.
    /// When response_type=id_token only, at_hash and c_hash should not be included.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithIdTokenOnly_ShouldNotIncludeHashClaims()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.IdToken]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var jwt = new JsonWebToken();
        var expectedIdToken = new EncodedJsonWebToken(jwt, "id_token_jwt");

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
        await _processor.ProcessAsync(request);

        // Assert
        _identityTokenService.Verify(
            s => s.CreateIdentityTokenAsync(
                session,
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                true,
                null,
                null),
            Times.Once);
    }

    // ───────────────────────────────────────────────────────────────────────
    // RFC 9396 - consent capture for authorization_details (#142).
    // The Pending bucket surfaces AD entries to the consent UI; the Granted
    // bucket carries the user's decision (which may narrow or deny the
    // request); token emission reads from Granted, with null → request
    // fallback for backward compatibility with PR #135 hosts.
    // ───────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Captures the <see cref="AuthorizedGrant"/> passed to
    /// <see cref="IAuthorizationCodeService.GenerateAuthorizationCodeAsync"/>. Tests
    /// inspect the captured grant's <see cref="AuthorizationContext"/> to assert what
    /// the processor emitted into the token-issuance path.
    /// </summary>
    private sealed class GrantCapture
    {
        public AuthorizedGrant? Grant { get; set; }
    }

    /// <summary>
    /// Wires up the strict Mocks for a successful authorization-code flow and returns a
    /// <see cref="GrantCapture"/> that fills in once <see cref="AuthorizationRequestProcessor.ProcessAsync"/>
    /// reaches the code-issuance step. Eliminates the four-line Setup boilerplate from
    /// each consent-side test.
    /// </summary>
    private GrantCapture SetupSuccessfulAuthCodeFlow(
        ValidAuthorizationRequest request,
        AuthSession session,
        UserConsents consents)
    {
        var capture = new GrantCapture();

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
            .Callback<AuthorizedGrant, TimeSpan>((grant, _) => capture.Grant = grant)
            .ReturnsAsync("code");

        return capture;
    }

    [Fact]
    public async Task ProcessAsync_AuthorizationDetailsPendingForConsent_ReturnsConsentRequired()
    {
        var pendingAd = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var request = CreateRequest(authorizationDetails: pendingAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(pendingAuthorizationDetails: pendingAd);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        var result = await _processor.ProcessAsync(request);

        var consentRequired = Assert.IsType<ConsentRequired>(result);
        Assert.Same(pendingAd, consentRequired.RequiredUserConsents.AuthorizationDetails);
    }

    [Fact]
    public async Task ProcessAsync_AuthorizationDetailsAllDenied_ReturnsAccessDenied()
    {
        // Provider returned Granted.AuthorizationDetails = [] (empty, not null) while the
        // request carried AD entries -- the canonical "user denied every entry" signal.
        var requestedAd = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(grantedAuthorizationDetails: new JsonArray());

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        var result = await _processor.ProcessAsync(request);

        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
    }

    [Fact]
    public async Task ProcessAsync_AuthorizationDetailsNarrowedByProvider_PropagatesNarrowToContext()
    {
        // Provider returns a narrower Granted.AuthorizationDetails than the request carried
        // -- the AuthorizationContext (and downstream token emission) reflects the narrow set.
        var requestedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500.00" });
        var narrowedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "200.00" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(grantedAuthorizationDetails: narrowedAd);

        var capture = SetupSuccessfulAuthCodeFlow(request, session, consents);

        await _processor.ProcessAsync(request);

        Assert.NotNull(capture.Grant);
        // Defensive DeepClone at the boundary (C2): the AuthorizationContext receives a clone,
        // not the same reference -- assert value-equality through the wire JSON instead.
        Assert.Equal(narrowedAd.ToJsonString(), capture.Grant.Context.AuthorizationDetails!.ToJsonString());
    }

    [Fact]
    public async Task ProcessAsync_ConsentDropsOneEntryFromMultiSet_TokenReflectsRemaining()
    {
        // RFC 9396 §5 partial-consent drop-entry. Client requested two entries, user
        // agreed to one. Consent layer is the right surface for this -- per-type
        // validators only see a single entry and cannot reason cross-entry.
        var requestedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation" },
            new JsonObject { ["type"] = "account_information" });
        var partialAd = new JsonArray(
            new JsonObject { ["type"] = "account_information" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(grantedAuthorizationDetails: partialAd);

        var capture = SetupSuccessfulAuthCodeFlow(request, session, consents);

        await _processor.ProcessAsync(request);

        Assert.NotNull(capture.Grant);
        // Defensive DeepClone at the boundary (C2): value-equality, not reference.
        Assert.Equal(partialAd.ToJsonString(), capture.Grant.Context.AuthorizationDetails!.ToJsonString());
        Assert.Single(capture.Grant.Context.AuthorizationDetails!);
    }

    [Fact]
    public async Task ProcessAsync_ConsentAppliesCrossDetailCapAcrossEntries_TokenReflectsCappedSet()
    {
        // RFC 9396 §5 cross-detail policy. Client requested three payment_initiation
        // entries of 500 each (total 1500); host policy caps total at 1000; consent
        // provider sees the entire list and returns the cross-cut narrow with the
        // last entry zeroed out. Per-type validators have no signal that the third
        // entry tips over the cap; consent layer does.
        var requestedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500" },
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500" },
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500" });
        var cappedAd = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500" },
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "500" },
            new JsonObject { ["type"] = "payment_initiation", ["amount"] = "0" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents(grantedAuthorizationDetails: cappedAd);

        var capture = SetupSuccessfulAuthCodeFlow(request, session, consents);

        await _processor.ProcessAsync(request);

        Assert.NotNull(capture.Grant);
        var emitted = capture.Grant.Context.AuthorizationDetails!;
        Assert.Equal(3, emitted.Count);
        Assert.Equal("0", emitted[2]!["amount"]!.GetValue<string>());
    }

    [Fact]
    public async Task ProcessAsync_LegacyProviderReturnsNullGrantedAd_FallsBackToRequestValue()
    {
        // Backward compat: a provider that has not been updated for #142 leaves
        // Granted.AuthorizationDetails as null. Emission falls back to the request's
        // (post-validator) AuthorizationDetails so PR #135 behaviour is preserved.
        var requestedAd = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var request = CreateRequest(authorizationDetails: requestedAd);
        var session = CreateAuthSession();
        var consents = CreateConsents();

        var capture = SetupSuccessfulAuthCodeFlow(request, session, consents);

        await _processor.ProcessAsync(request);

        Assert.NotNull(capture.Grant);
        // Defensive DeepClone at the boundary (C2): value-equality, not reference.
        Assert.Equal(requestedAd.ToJsonString(), capture.Grant.Context.AuthorizationDetails!.ToJsonString());
    }
}
