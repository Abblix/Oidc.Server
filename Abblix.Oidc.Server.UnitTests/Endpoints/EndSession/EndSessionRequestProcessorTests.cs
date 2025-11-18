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
using Abblix.Oidc.Server.Endpoints.EndSession;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession;

/// <summary>
/// Unit tests for <see cref="EndSessionRequestProcessor"/> verifying logout logic
/// per OIDC Session Management specification.
/// </summary>
public class EndSessionRequestProcessorTests
{
    private const string Issuer = "https://auth.example.com";

    private readonly Mock<ILogger<EndSessionRequestProcessor>> _logger;
    private readonly Mock<IAuthSessionService> _authSessionService;
    private readonly Mock<IIssuerProvider> _issuerProvider;
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly Mock<ILogoutNotifier> _logoutNotifier;
    private readonly EndSessionRequestProcessor _processor;

    public EndSessionRequestProcessorTests()
    {
        LicenseTestHelper.StartTest();

        _logger = new Mock<ILogger<EndSessionRequestProcessor>>();
        _authSessionService = new Mock<IAuthSessionService>(MockBehavior.Strict);
        _issuerProvider = new Mock<IIssuerProvider>(MockBehavior.Strict);
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        _logoutNotifier = new Mock<ILogoutNotifier>(MockBehavior.Strict);
        _processor = new EndSessionRequestProcessor(
            _logger.Object,
            _authSessionService.Object,
            _issuerProvider.Object,
            _clientInfoProvider.Object,
            _logoutNotifier.Object);
    }

    private static EndSessionRequest CreateEndSessionRequest(
        Uri? postLogoutRedirectUri = null,
        string? state = null)
    {
        return new EndSessionRequest
        {
            PostLogoutRedirectUri = postLogoutRedirectUri ?? new Uri("https://client.example.com/logout"),
            State = state,
            IdTokenHint = "id_token_hint",
        };
    }

    private static ValidEndSessionRequest CreateValidEndSessionRequest(
        EndSessionRequest? request = null,
        ClientInfo? clientInfo = null)
    {
        request ??= CreateEndSessionRequest();
        clientInfo ??= new ClientInfo("client_123");
        return new ValidEndSessionRequest(request, clientInfo);
    }

    private static AuthSession CreateAuthSession(
        string subject = "user_123",
        string sessionId = "session_123",
        params string[] affectedClientIds)
    {
        var session = new AuthSession(
            subject,
            sessionId,
            DateTimeOffset.UtcNow,
            "local");

        foreach (var clientId in affectedClientIds)
        {
            session.AffectedClientIds.Add(clientId);
        }

        return session;
    }

    /// <summary>
    /// Verifies successful logout with authenticated session.
    /// Per OIDC Session Management, processor should sign out user and notify clients.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithAuthenticatedSession_ShouldSignOutAndReturnSuccess()
    {
        // Arrange
        var request = CreateValidEndSessionRequest();
        var authSession = CreateAuthSession();

        _authSessionService
            .Setup(s => s.AuthenticateAsync())
            .ReturnsAsync(authSession);

        _authSessionService
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(Issuer);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.NotNull(response.PostLogoutRedirectUri);
        _authSessionService.Verify(s => s.AuthenticateAsync(), Times.Once);
        _authSessionService.Verify(s => s.SignOutAsync(), Times.Once);
    }

    /// <summary>
    /// Verifies logout without authenticated session.
    /// Per OIDC Session Management, processor should return success without signing out.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithoutAuthenticatedSession_ShouldReturnSuccessWithoutSignOut()
    {
        // Arrange
        var request = CreateValidEndSessionRequest();

        _authSessionService
            .Setup(s => s.AuthenticateAsync())
            .ReturnsAsync((AuthSession?)null);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.NotNull(response.PostLogoutRedirectUri);
        Assert.Empty(response.FrontChannelLogoutRequestUris);
        _authSessionService.Verify(s => s.AuthenticateAsync(), Times.Once);
        _authSessionService.Verify(s => s.SignOutAsync(), Times.Never);
    }

    /// <summary>
    /// Verifies post-logout redirect URI with state parameter.
    /// Per OIDC Session Management, state should be appended to redirect URI.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithState_ShouldAppendStateToRedirectUri()
    {
        // Arrange
        var state = "state_value_123";
        var redirectUri = new Uri("https://client.example.com/logout");
        var endSessionRequest = CreateEndSessionRequest(redirectUri, state);
        var request = CreateValidEndSessionRequest(endSessionRequest);

        _authSessionService
            .Setup(s => s.AuthenticateAsync())
            .ReturnsAsync((AuthSession?)null);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.NotNull(response.PostLogoutRedirectUri);
        Assert.Contains("state=state_value_123", response.PostLogoutRedirectUri.Query);
    }

    /// <summary>
    /// Verifies post-logout redirect URI without state parameter.
    /// State should not be appended if not provided.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithoutState_ShouldNotModifyRedirectUri()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/logout");
        var endSessionRequest = CreateEndSessionRequest(redirectUri, state: null);
        var request = CreateValidEndSessionRequest(endSessionRequest);

        _authSessionService
            .Setup(s => s.AuthenticateAsync())
            .ReturnsAsync((AuthSession?)null);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.NotNull(response.PostLogoutRedirectUri);
        Assert.Equal(redirectUri.ToString(), response.PostLogoutRedirectUri.ToString());
    }

    /// <summary>
    /// Verifies client notification for affected clients.
    /// Per OIDC Front-Channel Logout, processor should notify all affected clients.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithAffectedClients_ShouldNotifyAllClients()
    {
        // Arrange
        var request = CreateValidEndSessionRequest();
        var authSession = CreateAuthSession("user_123", "session_123", "client_1", "client_2");

        var client1 = new ClientInfo("client_1");
        var client2 = new ClientInfo("client_2");

        _authSessionService
            .Setup(s => s.AuthenticateAsync())
            .ReturnsAsync(authSession);

        _authSessionService
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(Issuer);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("client_1"))
            .ReturnsAsync(client1);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("client_2"))
            .ReturnsAsync(client2);

        _logoutNotifier
            .Setup(n => n.NotifyClientAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out _));
        _logoutNotifier.Verify(n => n.NotifyClientAsync(client1, It.IsAny<LogoutContext>()), Times.Once);
        _logoutNotifier.Verify(n => n.NotifyClientAsync(client2, It.IsAny<LogoutContext>()), Times.Once);
    }

    /// <summary>
    /// Verifies client notification skips non-existent clients.
    /// If client info is not found, notification should be skipped.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithNonExistentClient_ShouldSkipNotification()
    {
        // Arrange
        var request = CreateValidEndSessionRequest();
        var authSession = CreateAuthSession("user_123", "session_123", "client_1", "client_missing");

        var client1 = new ClientInfo("client_1");

        _authSessionService
            .Setup(s => s.AuthenticateAsync())
            .ReturnsAsync(authSession);

        _authSessionService
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(Issuer);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("client_1"))
            .ReturnsAsync(client1);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("client_missing"))
            .ReturnsAsync((ClientInfo?)null);

        _logoutNotifier
            .Setup(n => n.NotifyClientAsync(client1, It.IsAny<LogoutContext>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out _));
        _logoutNotifier.Verify(n => n.NotifyClientAsync(client1, It.IsAny<LogoutContext>()), Times.Once);
        _logoutNotifier.Verify(
            n => n.NotifyClientAsync(It.Is<ClientInfo>(c => c.ClientId == "client_missing"), It.IsAny<LogoutContext>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies logout context contains correct session and subject.
    /// Logout notifications should include session ID and subject ID.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldCreateLogoutContextWithSessionAndSubject()
    {
        // Arrange
        var request = CreateValidEndSessionRequest();
        var authSession = CreateAuthSession("user_456", "session_789", "client_1");

        var client1 = new ClientInfo("client_1");
        LogoutContext? capturedContext = null;

        _authSessionService
            .Setup(s => s.AuthenticateAsync())
            .ReturnsAsync(authSession);

        _authSessionService
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(Issuer);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("client_1"))
            .ReturnsAsync(client1);

        _logoutNotifier
            .Setup(n => n.NotifyClientAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .Callback<ClientInfo, LogoutContext>((_, context) => capturedContext = context)
            .Returns(Task.CompletedTask);

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        Assert.NotNull(capturedContext);
        Assert.Equal("session_789", capturedContext.SessionId);
        Assert.Equal("user_456", capturedContext.SubjectId);
        Assert.Equal(Issuer, capturedContext.Issuer);
    }

    /// <summary>
    /// Verifies front-channel logout URIs are returned in response.
    /// Per OIDC Front-Channel Logout, response should include logout URIs.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldReturnFrontChannelLogoutUris()
    {
        // Arrange
        var request = CreateValidEndSessionRequest();
        var authSession = CreateAuthSession("user_123", "session_123", "client_1");

        var client1 = new ClientInfo("client_1");

        _authSessionService
            .Setup(s => s.AuthenticateAsync())
            .ReturnsAsync(authSession);

        _authSessionService
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(Issuer);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("client_1"))
            .ReturnsAsync(client1);

        _logoutNotifier
            .Setup(n => n.NotifyClientAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .Callback<ClientInfo, LogoutContext>((_, context) =>
            {
                context.FrontChannelLogoutRequestUris.Add(new Uri("https://client1.example.com/logout"));
            })
            .Returns(Task.CompletedTask);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.Single(response.FrontChannelLogoutRequestUris);
        Assert.Equal("https://client1.example.com/logout", response.FrontChannelLogoutRequestUris.First().ToString());
    }

    /// <summary>
    /// Verifies sign out is called before client notification.
    /// Tests execution order.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldSignOutBeforeNotifyingClients()
    {
        // Arrange
        var request = CreateValidEndSessionRequest();
        var authSession = CreateAuthSession("user_123", "session_123", "client_1");

        var client1 = new ClientInfo("client_1");
        var callOrder = new List<string>();

        _authSessionService
            .Setup(s => s.AuthenticateAsync())
            .ReturnsAsync(authSession);

        _authSessionService
            .Setup(s => s.SignOutAsync())
            .Callback(() => callOrder.Add("signout"))
            .Returns(Task.CompletedTask);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(Issuer);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("client_1"))
            .ReturnsAsync(client1);

        _logoutNotifier
            .Setup(n => n.NotifyClientAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .Callback(() => callOrder.Add("notify"))
            .Returns(Task.CompletedTask);

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        Assert.Equal(2, callOrder.Count);
        Assert.Equal("signout", callOrder[0]);
        Assert.Equal("notify", callOrder[1]);
    }

    /// <summary>
    /// Verifies issuer is retrieved for logout context.
    /// IssuerProvider should be called to get issuer.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldRetrieveIssuerForLogoutContext()
    {
        // Arrange
        var request = CreateValidEndSessionRequest();
        var authSession = CreateAuthSession("user_123", "session_123", "client_1");

        var client1 = new ClientInfo("client_1");

        _authSessionService
            .Setup(s => s.AuthenticateAsync())
            .ReturnsAsync(authSession);

        _authSessionService
            .Setup(s => s.SignOutAsync())
            .Returns(Task.CompletedTask);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(Issuer);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("client_1"))
            .ReturnsAsync(client1);

        _logoutNotifier
            .Setup(n => n.NotifyClientAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .Returns(Task.CompletedTask);

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        _issuerProvider.Verify(p => p.GetIssuer(), Times.Once);
    }

    /// <summary>
    /// Verifies response includes post-logout redirect URI from request.
    /// Per OIDC Session Management, redirect URI should be preserved.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldReturnPostLogoutRedirectUriFromRequest()
    {
        // Arrange
        var redirectUri = new Uri("https://custom.example.com/logout-callback");
        var endSessionRequest = CreateEndSessionRequest(redirectUri);
        var request = CreateValidEndSessionRequest(endSessionRequest);

        _authSessionService
            .Setup(s => s.AuthenticateAsync())
            .ReturnsAsync((AuthSession?)null);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.Equal(redirectUri.ToString(), response.PostLogoutRedirectUri!.ToString());
    }

}
