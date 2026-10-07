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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
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
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Abblix.Oidc.Server.Features.ReusePrevention;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

/// <summary>
/// Unit tests for <see cref="AuthorizationRequestProcessor"/> verifying authorization
/// request processing logic per OAuth 2.0 and OIDC specifications.
/// </summary>
public partial class AuthorizationRequestProcessorTests
{
    private readonly Mock<IAuthSessionService> _authSessionService;
    private readonly Mock<ISessionClientRegistry> _sessionClients = new();
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
                It.IsAny<JsonArray?>(), It.IsAny<JsonArray?>(), It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((JsonArray? ad, JsonArray? _, ClientInfo _, CancellationToken _) => ad ?? new JsonArray());

        _timeProvider = new FakeTimeProvider();

        // No cutoff recorded is the ordinary case; the tests about revocation build their own.
        _cutoffChecker
            .Setup(c => c.IsSessionRefusedAsync(It.IsAny<AuthSession>()))
            .ReturnsAsync(false);

        // A real ConsentConstraintEnforcer (not a mock) so the anti-escalation backstop is
        // exercised end-to-end through the processor - granted scopes/resources that exceed the
        // request must throw before the grant is built.
        _sessionClients
            .Setup(r => r.GetClientsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);

        _processor = ProcessorWith(new ConsentConstraintEnforcer(
            NullLogger<ConsentConstraintEnforcer>.Instance, _authorizationDetailsPolicy.Object));
    }

    /// <summary>
    /// The processor over this fixture's collaborators and the consent backstop given.
    /// </summary>
    private AuthorizationRequestProcessor ProcessorWith(IConsentConstraintEnforcer consentConstraintEnforcer)
    {
        return new AuthorizationRequestProcessor(
            _authSessionService.Object,
            _sessionClients.Object,
            _consentsProvider.Object,
            _cutoffChecker.Object,
            new SubjectTypeConverter(),
            _timeProvider,
            [
                new AuthorizationCodeBuilder(_authorizationCodeService.Object, Mock.Of<IAuthorizationValueReuseDetector>()),
                new TokenResponseBuilder(_accessTokenService.Object),
                new IdTokenResponseBuilder(_identityTokenService.Object),
            ],
            consentConstraintEnforcer);
    }

    private static ValidAuthorizationRequest CreateRequest(
        string[]? responseType = null,
        string[]? prompt = null,
        TimeSpan? maxAge = null,
        string[]? acrValues = null,
        string[]? scope = null,
        JsonArray? authorizationDetails = null,
        TimeSpan? defaultMaxAge = null,
        string[]? defaultAcrValues = null,
        string? idTokenHintSubject = null,
        string? clientId = null,
        DateTimeOffset? promptedAt = null,
        ResourceDefinition[]? resources = null)
    {
        clientId ??= TestConstants.DefaultClientId;

        var authRequest = new AuthorizationRequest
        {
            ClientId = clientId,
            ResponseType = responseType ?? [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            Scope = scope ?? [Scopes.OpenId],
            Prompt = prompt,
            MaxAge = maxAge,
            AcrValues = acrValues,
            AuthorizationDetails = authorizationDetails,
            // Every page the prompt names was shown at that moment
            Prompted = promptedAt is { } shownAt ? prompt?.ToDictionary(value => value, _ => shownAt) : null,
        };

        var clientInfo = new ClientInfo(clientId)
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
            Resources = resources ?? [],
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
            AuthenticationTime: authTime ?? TimeProvider.System.GetUtcNow(),
            IdentityProvider: "local")
        {
            AuthContextClassRef = acr,
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
}
