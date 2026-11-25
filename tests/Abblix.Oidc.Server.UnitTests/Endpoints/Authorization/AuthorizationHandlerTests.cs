// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using System.Linq;
using Core = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

/// <summary>
/// Unit tests for <see cref="AuthorizationHandler"/> verifying request orchestration
/// (fetch → validate → process) per OAuth 2.0/OIDC specifications.
/// </summary>
public class AuthorizationHandlerTests
{
    private readonly Mock<IAuthorizationRequestFetcher> _fetcher;
    private readonly Mock<IAuthorizationRequestValidator> _validator;
    private readonly Mock<IAuthorizationRequestProcessor> _processor;
    private readonly Mock<IAuthorizationResponseEncoder> _encoder;
    private readonly Mock<IClientInfoProvider> _clients;
    private readonly Mock<IRedirectUriTrustPolicy> _redirectUriTrust;
    private readonly AuthorizationHandler _handler;

    public AuthorizationHandlerTests()
    {
        _fetcher = new Mock<IAuthorizationRequestFetcher>(MockBehavior.Strict);
        _validator = new Mock<IAuthorizationRequestValidator>(MockBehavior.Strict);
        _processor = new Mock<IAuthorizationRequestProcessor>(MockBehavior.Strict);
        _encoder = new Mock<IAuthorizationResponseEncoder>(MockBehavior.Strict);
        _encoder.Setup(e => e.EncodeAsync(
                TestTenant.Matched, It.IsAny<Core.AuthorizationResponse>(), It.IsAny<IClientInfoProvider>()))
            .Returns<TenantDefinition, Core.AuthorizationResponse, IClientInfoProvider>(
                (_, response, _) => Task.FromResult(response));
        _clients = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        _clients
            .Setup(c => c.FindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
            .ReturnsAsync(new ClientInfo(TestConstants.DefaultClientId));
        _redirectUriTrust = new Mock<IRedirectUriTrustPolicy>(MockBehavior.Strict);
        _redirectUriTrust
            .Setup(t => t.IsTrustedAsync(TestTenant.Matched, It.IsAny<ClientInfo>()))
            .ReturnsAsync(true);
        _sessions = new Mock<IAuthSessionService>(MockBehavior.Strict);
        SignedIn(new AuthSession("subject", "session", AuthenticatedAt, "local"));
        _cutoffs = new Mock<IRevocationCutoffChecker>(MockBehavior.Strict);
        _cutoffs
            .Setup(c => c.IsSessionRefusedAsync(TestTenant.Matched, It.IsAny<AuthSession>()))
            .ReturnsAsync(false);
        _handler = new AuthorizationHandler(
            _clients.Object,
            _fetcher.Object,
            _validator.Object,
            _processor.Object,
            _encoder.Object,
            _redirectUriTrust.Object,
            _sessions.Object,
            _cutoffs.Object);
    }

    private readonly Mock<IAuthSessionService> _sessions;
    private readonly Mock<IRevocationCutoffChecker> _cutoffs;

    private static readonly DateTimeOffset AuthenticatedAt = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private void SignedIn(params AuthSession[] sessions)
        => _sessions.Setup(s => s.GetAvailableAuthSessions()).Returns(sessions.ToAsyncEnumerable());

    /// <summary>
    /// RFC 9700 section 4.11.2: the server "MUST always authenticate the user first and, with the exception of the
    /// silent authentication use case, prompt the user for credentials when needed, before redirecting the user". An
    /// error bound for the client's redirect URI while nobody is signed in, or only somebody whose session a revocation
    /// refuses, sends the end user to log in, carrying the request as it was fetched, and nothing is encoded.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HandleAsync_AnErrorWithoutAnAuthenticatedUser_SendsToLoginFirst(bool revokedSessionHeld)
    {
        var request = CreateRequest();
        SetUpValidationError(request, request.RedirectUri);
        if (revokedSessionHeld)
        {
            SignedIn(new AuthSession("subject", "revoked", AuthenticatedAt, "local"));
            _cutoffs
                .Setup(c => c.IsSessionRefusedAsync(TestTenant.Matched, It.IsAny<AuthSession>()))
                .ReturnsAsync(true);
        }
        else
        {
            SignedIn();
        }

        var login = Assert.IsType<LoginRequired>(await _handler.HandleAsync(SingleIssuer.Tenant, request));

        Assert.Same(request, login.Model);
        _encoder.Verify(
            e => e.EncodeAsync(TestTenant.Matched, It.IsAny<Core.AuthorizationResponse>(), It.IsAny<IClientInfoProvider>()),
            Times.Never);
    }

    /// <summary>
    /// The exceptions to the login first: a silent request, which may show no page, and an error with no redirect URI,
    /// which the server answers itself. Both are answered at once, as an error.
    /// </summary>
    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task HandleAsync_ASilentOrUnredirectedErrorWithoutAUser_IsAnsweredAtOnce(bool silent, bool hasRedirectUri)
    {
        var request = CreateRequest() with { Prompt = silent ? [Prompts.None] : null };
        SetUpValidationError(request, hasRedirectUri ? request.RedirectUri : null);
        SignedIn();

        var error = Assert.IsType<AuthorizationError>(await _handler.HandleAsync(SingleIssuer.Tenant, request));

        Assert.Equal(ErrorCodes.InvalidScope, error.Error);
        Assert.Equal(hasRedirectUri ? request.RedirectUri : null, error.RedirectUri);
    }

    /// <summary>
    /// The login is owed only before an error that is redirected: an error for a client whose redirect URIs are not
    /// trusted is answered by the server at once, with nobody signed in, and nobody is asked who is.
    /// </summary>
    [Fact]
    public async Task HandleAsync_AnUntrustedClientsErrorWithoutAUser_IsAnsweredAtOnce()
    {
        var request = CreateRequest();
        SetUpValidationError(request, request.RedirectUri);
        SignedIn();
        _redirectUriTrust
            .Setup(t => t.IsTrustedAsync(TestTenant.Matched, It.IsAny<ClientInfo>()))
            .ReturnsAsync(false);

        var error = Assert.IsType<AuthorizationError>(await _handler.HandleAsync(SingleIssuer.Tenant, request));

        Assert.Null(error.RedirectUri);
        _sessions.Verify(s => s.GetAvailableAuthSessions(), Times.Never);
    }

    /// <summary>
    /// The trust in the client's redirect URIs is decided once per request, so the login owed before an error and the
    /// error kept at the server rest on one verdict: a policy whose answer changes while the request is answered, as a
    /// registration removed meanwhile changes it, cannot have the error skip the login and still be redirected.
    /// </summary>
    [Fact]
    public async Task HandleAsync_AVerdictChangingDuringTheRequest_RedirectsNothingWithoutALogin()
    {
        var request = CreateRequest();
        SetUpValidationError(request, request.RedirectUri);
        SignedIn();
        _redirectUriTrust
            .SetupSequence(t => t.IsTrustedAsync(TestTenant.Matched, It.IsAny<ClientInfo>()))
            .ReturnsAsync(false)
            .ReturnsAsync(true);

        var error = Assert.IsType<AuthorizationError>(await _handler.HandleAsync(SingleIssuer.Tenant, request));

        Assert.Null(error.RedirectUri);
        _redirectUriTrust.Verify(t => t.IsTrustedAsync(TestTenant.Matched, It.IsAny<ClientInfo>()), Times.Once);
    }

    /// <summary>
    /// A trusted or untrusted client's error answered with a session asks the policy once.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task HandleAsync_AnErrorWithASession_AsksThePolicyOnce(bool trusted)
    {
        var request = CreateRequest();
        SetUpValidationError(request, request.RedirectUri);
        _redirectUriTrust
            .Setup(t => t.IsTrustedAsync(TestTenant.Matched, It.IsAny<ClientInfo>()))
            .ReturnsAsync(trusted);

        var error = Assert.IsType<AuthorizationError>(await _handler.HandleAsync(SingleIssuer.Tenant, request));

        Assert.Equal(trusted ? request.RedirectUri : null, error.RedirectUri);
        _redirectUriTrust.Verify(t => t.IsTrustedAsync(TestTenant.Matched, It.IsAny<ClientInfo>()), Times.Once);
    }

    /// <summary>
    /// An error naming no client is not going to be redirected, so it owes no login either, with nobody signed in.
    /// </summary>
    [Fact]
    public async Task HandleAsync_AnErrorNamingNoClientWithoutAUser_IsAnsweredAtOnce()
    {
        var request = CreateRequest() with { ClientId = null };
        SetUpValidationError(request, request.RedirectUri);
        SignedIn();

        var error = Assert.IsType<AuthorizationError>(await _handler.HandleAsync(SingleIssuer.Tenant, request));

        Assert.Null(error.RedirectUri);
        _sessions.Verify(s => s.GetAvailableAuthSessions(), Times.Never);
    }

    /// <summary>
    /// An error carrying a redirect URI but naming no client has no client whose redirect URIs could be trusted, so the
    /// server answers it.
    /// </summary>
    [Fact]
    public async Task HandleAsync_AnErrorNamingNoClient_StaysAtTheServer()
    {
        var request = CreateRequest() with { ClientId = null };
        SetUpValidationError(request, request.RedirectUri);

        var error = Assert.IsType<AuthorizationError>(await _handler.HandleAsync(SingleIssuer.Tenant, request));

        Assert.Null(error.RedirectUri);
    }

    private void SetUpValidationError(AuthorizationRequest request, Uri? redirectUri)
    {
        _fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<AuthorizationRequest, AuthorizationRequestValidationError>)request);
        _validator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>)
                new AuthorizationRequestValidationError(
                    ErrorCodes.InvalidScope, "The scope is not allowed", redirectUri, ResponseModes.Query));
    }

    /// <summary>
    /// RFC 9700 section 4.11.2: the server "SHOULD only automatically redirect the user agent if it trusts the
    /// redirection URI". An error for a client the policy does not trust, or for one no longer found, is answered by the
    /// server without its redirect URI or a packed JWT, so the adapters answer it with status 400; a trusted client's
    /// error is redirected as before.
    /// </summary>
    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    public async Task HandleAsync_AnError_ReachesTheClientOnlyWhenItsRedirectUrisAreTrusted(
        bool found, bool trusted, bool redirected)
    {
        var request = CreateRequest();
        var fetchError = new AuthorizationRequestValidationError(
            ErrorCodes.InvalidScope, "The scope is not allowed", request.RedirectUri, ResponseModes.QueryJwt);
        _fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<AuthorizationRequest, AuthorizationRequestValidationError>)fetchError);
        _encoder.Setup(e => e.EncodeAsync(
                TestTenant.Matched, It.IsAny<Core.AuthorizationResponse>(), It.IsAny<IClientInfoProvider>()))
            .Returns<TenantDefinition, Core.AuthorizationResponse, IClientInfoProvider>((_, response, _) =>
            {
                ((ClientDeliveredResponse)response).ResponseJwt = "packed";
                return Task.FromResult(response);
            });
        if (!found)
        {
            _clients
                .Setup(c => c.FindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
                .ReturnsAsync(ClientAbsence.Unknown);
        }
        _redirectUriTrust
            .Setup(t => t.IsTrustedAsync(TestTenant.Matched, It.IsAny<ClientInfo>()))
            .ReturnsAsync(trusted);

        var error = Assert.IsType<AuthorizationError>(await _handler.HandleAsync(SingleIssuer.Tenant, request));

        Assert.Equal(ErrorCodes.InvalidScope, error.Error);
        Assert.Equal(redirected ? request.RedirectUri : null, error.RedirectUri);
        Assert.Equal(redirected ? "packed" : null, error.ResponseJwt);
    }

    /// <summary>
    /// A successful authorization follows the end user's consent to the client, so it reaches an untrusted client too,
    /// and the policy is not asked.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ASuccess_ReachesAnUntrustedClient()
    {
        var request = CreateRequest();
        var validRequest = new ValidAuthorizationRequest(new AuthorizationValidationContext(request)
        {
            Clients = Mock.Of<IClientInfoProvider>(),
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        });
        var success = new SuccessfullyAuthenticated(request, ResponseModes.Query, "session", [])
        {
            SessionPersistence = Abblix.Oidc.Server.Features.UserAuthentication.SessionPersistence.BrowserSession,
        };
        _fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<AuthorizationRequest, AuthorizationRequestValidationError>)request);
        _validator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>)validRequest);
        _processor.Setup(p => p.ProcessAsync(TestTenant.Matched, validRequest)).ReturnsAsync(success);
        _redirectUriTrust
            .Setup(t => t.IsTrustedAsync(TestTenant.Matched, It.IsAny<ClientInfo>()))
            .ReturnsAsync(false);

        Assert.Same(success, await _handler.HandleAsync(SingleIssuer.Tenant, request));
        _redirectUriTrust.VerifyNoOtherCalls();
    }

    private static AuthorizationRequest CreateRequest() => new()
    {
        ClientId = TestConstants.DefaultClientId,
        ResponseType = [ResponseTypes.Code],
        RedirectUri = new Uri("https://client.example.com/callback"),
        Scope = [Scopes.OpenId],
    };

    /// <summary>
    /// Verifies successful authorization flow: fetch → validate → process.
    /// Tests happy path where all steps succeed.
    /// </summary>
    [Fact]
    public async Task HandleAsync_SuccessfulFlow_ShouldCallAllComponents()
    {
        // Arrange
        var request = CreateRequest();
        var fetchedRequest = CreateRequest();
        var validationContext = new AuthorizationValidationContext(fetchedRequest)
        {
            Clients = Mock.Of<IClientInfoProvider>(),
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        };
        var validRequest = new ValidAuthorizationRequest(validationContext);
        var processedResponse = new AuthorizationError(request, ErrorCodes.ConsentRequired, "",
            ResponseModes.Query, request.RedirectUri);

        _fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<AuthorizationRequest, AuthorizationRequestValidationError>)(fetchedRequest));

        _validator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, fetchedRequest, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>)(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(TestTenant.Matched, validRequest))
            .ReturnsAsync(processedResponse);

        // Act
        var result = await _handler.HandleAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.NotNull(result);
        _fetcher.Verify(f => f.FetchAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()), Times.Once);
        _validator.Verify(v => v.ValidateAsync(TestTenant.Matched, fetchedRequest, It.IsAny<IClientInfoProvider>()), Times.Once);
        _processor.Verify(p => p.ProcessAsync(TestTenant.Matched, validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies fetch error handling.
    /// Per OAuth 2.0, fetch errors (PAR, request object) should return error response.
    /// </summary>
    [Fact]
    public async Task HandleAsync_FetchError_ShouldReturnAuthorizationError()
    {
        // Arrange
        var request = CreateRequest();
        var fetchError = new AuthorizationRequestValidationError(
            ErrorCodes.InvalidRequest,
            "Failed to fetch request object",
            request.RedirectUri,
            ResponseModes.Query);

        _fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<AuthorizationRequest, AuthorizationRequestValidationError>)(fetchError));

        // Act
        var result = await _handler.HandleAsync(SingleIssuer.Tenant, request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Equal("Failed to fetch request object", error.ErrorDescription);
        _fetcher.Verify(f => f.FetchAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()), Times.Once);
        _validator.VerifyNoOtherCalls();
        _processor.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies validation error handling.
    /// Per OAuth 2.0, validation errors should return error response.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ValidationError_ShouldReturnAuthorizationError()
    {
        // Arrange
        var request = CreateRequest();
        var fetchedRequest = CreateRequest();
        var validationError = new AuthorizationRequestValidationError(
            ErrorCodes.InvalidScope,
            "Invalid scope requested",
            request.RedirectUri,
            ResponseModes.Query);

        _fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<AuthorizationRequest, AuthorizationRequestValidationError>)(fetchedRequest));

        _validator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, fetchedRequest, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>)(validationError));

        // Act
        var result = await _handler.HandleAsync(SingleIssuer.Tenant, request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.InvalidScope, error.Error);
        Assert.Equal("Invalid scope requested", error.ErrorDescription);
        _fetcher.Verify(f => f.FetchAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()), Times.Once);
        _validator.Verify(v => v.ValidateAsync(TestTenant.Matched, fetchedRequest, It.IsAny<IClientInfoProvider>()), Times.Once);
        _processor.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies request passing from fetcher to validator.
    /// Fetched request should be validated, not original request.
    /// Critical for PAR and request object support.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldPassFetchedRequestToValidator()
    {
        // Arrange
        var originalRequest = CreateRequest();
        var fetchedRequest = new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
            State = "modified_state",
        };
        var validationContext = new AuthorizationValidationContext(fetchedRequest)
        {
            Clients = Mock.Of<IClientInfoProvider>(),
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        };
        var validRequest = new ValidAuthorizationRequest(validationContext);
        var processedResponse = new AuthorizationError(fetchedRequest, ErrorCodes.ConsentRequired, "",
            ResponseModes.Query, fetchedRequest.RedirectUri);

        _fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, originalRequest, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<AuthorizationRequest, AuthorizationRequestValidationError>)(fetchedRequest));

        _validator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, It.Is<AuthorizationRequest>(r => r.State == "modified_state"), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>)(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(TestTenant.Matched, validRequest))
            .ReturnsAsync(processedResponse);

        // Act
        await _handler.HandleAsync(SingleIssuer.Tenant, originalRequest);

        // Assert
        _validator.Verify(v => v.ValidateAsync(
            TestTenant.Matched,
            It.Is<AuthorizationRequest>(r => r.State == "modified_state"),
            It.IsAny<IClientInfoProvider>()), Times.Once);
    }

    /// <summary>
    /// Verifies error response includes error code.
    /// Per OAuth 2.0, error responses MUST include error parameter.
    /// </summary>
    [Fact]
    public async Task HandleAsync_OnError_ShouldIncludeErrorCode()
    {
        // Arrange
        var request = CreateRequest();
        var fetchError = new AuthorizationRequestValidationError(
            ErrorCodes.UnauthorizedClient,
            "Client not authorized",
            request.RedirectUri,
            ResponseModes.Query);

        _fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync((Result<AuthorizationRequest, AuthorizationRequestValidationError>)(fetchError));

        // Act
        var result = await _handler.HandleAsync(SingleIssuer.Tenant, request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.NotNull(error.Error);
        Assert.NotEmpty(error.Error);
        Assert.Equal(ErrorCodes.UnauthorizedClient, error.Error);
    }

    /// <summary>
    /// Verifies sequential execution: fetch before validate before process.
    /// Tests that components are called in correct order.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldCallComponentsInOrder()
    {
        // Arrange
        var request = CreateRequest();
        var fetchedRequest = CreateRequest();
        var validationContext = new AuthorizationValidationContext(fetchedRequest)
        {
            Clients = Mock.Of<IClientInfoProvider>(),
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        };
        var validRequest = new ValidAuthorizationRequest(validationContext);
        var processedResponse = new AuthorizationError(request, ErrorCodes.ConsentRequired, "",
            ResponseModes.Query, request.RedirectUri);

        var callOrder = new System.Collections.Generic.List<string>();

        _fetcher
            .Setup(f => f.FetchAsync(TestTenant.Matched, request, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(() =>
            {
                callOrder.Add("fetch");
                return (Result<AuthorizationRequest, AuthorizationRequestValidationError>)(fetchedRequest);
            });

        _validator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, fetchedRequest, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(() =>
            {
                callOrder.Add("validate");
                return (Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>)(validRequest);
            });

        _processor
            .Setup(p => p.ProcessAsync(TestTenant.Matched, validRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("process");
                return processedResponse;
            });

        // Act
        await _handler.HandleAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.Equal(3, callOrder.Count);
        Assert.Equal("fetch", callOrder[0]);
        Assert.Equal("validate", callOrder[1]);
        Assert.Equal("process", callOrder[2]);
    }
}
