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
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.Tokens;
using Moq;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Features.LogoutNotification;

/// <summary>
/// Unit tests for <see cref="BackChannelLogoutNotifier"/> verifying back-channel logout notification
/// per OpenID Connect Back-Channel Logout specification.
/// </summary>
public class BackChannelLogoutNotifierTests
{
    private readonly Mock<ILogoutTokenService> _logoutTokenService;
    private readonly Mock<ILogoutTokenSender> _logoutTokenSender;
    private readonly BackChannelLogoutNotifier _notifier;

    public BackChannelLogoutNotifierTests()
    {
        _logoutTokenService = new Mock<ILogoutTokenService>(MockBehavior.Strict);
        _logoutTokenSender = new Mock<ILogoutTokenSender>(MockBehavior.Strict);
        _notifier = new BackChannelLogoutNotifier(_logoutTokenService.Object, _logoutTokenSender.Object);
    }

    private static ClientInfo CreateClientInfo(BackChannelLogoutOptions? backChannelLogout)
    {
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId)
        {
            BackChannelLogout = backChannelLogout
        };
        return clientInfo;
    }

    private static ClientInfo CreateClientInfoWithBackChannelLogout()
    {
        return CreateClientInfo(new BackChannelLogoutOptions(
            new Uri("https://client.example.com/backchannel_logout"),
            RequiresSessionId: true));
    }

    private static LogoutContext CreateLogoutContext(
        string? sessionId = null,
        string? subjectId = null,
        string? issuer = null)
    {
        return new LogoutContext(
            sessionId ?? "session_123",
            subjectId ?? "user_123",
            issuer ?? "https://server.example.com");
    }

    private static EncodedJsonWebToken CreateLogoutToken()
    {
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new System.Text.Json.Nodes.JsonObject()),
            Payload = new JsonWebTokenPayload(new System.Text.Json.Nodes.JsonObject())
        };
        return new EncodedJsonWebToken(token, "encoded.jwt.token");
    }

    /// <summary>
    /// Verifies FrontChannelLogoutSupported is false.
    /// Per OpenID Connect, BackChannelLogoutNotifier only supports back-channel logout.
    /// </summary>
    [Fact]
    public void FrontChannelLogoutSupported_ShouldBeFalse()
    {
        // Assert
        Assert.False(_notifier.FrontChannelLogoutSupported);
    }

    /// <summary>
    /// Verifies FrontChannelLogoutSessionSupported is false.
    /// Per OpenID Connect, BackChannelLogoutNotifier does not support front-channel logout sessions.
    /// </summary>
    [Fact]
    public void FrontChannelLogoutSessionSupported_ShouldBeFalse()
    {
        // Assert
        Assert.False(_notifier.FrontChannelLogoutSessionSupported);
    }

    /// <summary>
    /// Verifies BackChannelLogoutSupported is true.
    /// Per OpenID Connect Back-Channel Logout specification, this notifier supports back-channel logout.
    /// </summary>
    [Fact]
    public void BackChannelLogoutSupported_ShouldBeTrue()
    {
        // Assert
        Assert.True(_notifier.BackChannelLogoutSupported);
    }

    /// <summary>
    /// Verifies BackChannelLogoutSessionSupported is true.
    /// Per OpenID Connect, back-channel logout with session support is enabled.
    /// </summary>
    [Fact]
    public void BackChannelLogoutSessionSupported_ShouldBeTrue()
    {
        // Assert
        Assert.True(_notifier.BackChannelLogoutSessionSupported);
    }

    /// <summary>
    /// Verifies successful notification when client has back-channel logout configured.
    /// Per OpenID Connect Back-Channel Logout, logout token should be created and sent.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithBackChannelLogout_ShouldCreateAndSendLogoutToken()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(clientInfo, logoutContext),
            Times.Once);
        _logoutTokenSender.Verify(
            s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken),
            Times.Once);
    }

    /// <summary>
    /// Verifies no action when client has no back-channel logout configured.
    /// Per OpenID Connect, clients without back-channel logout should not be notified.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithoutBackChannelLogout_ShouldReturnEarly()
    {
        // Arrange
        var clientInfo = CreateClientInfo(backChannelLogout: null);
        var logoutContext = CreateLogoutContext();

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        _logoutTokenService.VerifyNoOtherCalls();
        _logoutTokenSender.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies correct ClientInfo is passed to logout token service.
    /// Token creation must use the correct client information.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_ShouldPassCorrectClientInfoToTokenService()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();

        ClientInfo? capturedClientInfo = null;

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .Callback<ClientInfo, LogoutContext>((ci, _) => capturedClientInfo = ci)
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.Same(clientInfo, capturedClientInfo);
    }

    /// <summary>
    /// Verifies correct LogoutContext is passed to logout token service.
    /// Token creation must use the correct logout context information.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_ShouldPassCorrectLogoutContextToTokenService()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();

        LogoutContext? capturedContext = null;

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .Callback<ClientInfo, LogoutContext>((_, lc) => capturedContext = lc)
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.Same(logoutContext, capturedContext);
    }

    /// <summary>
    /// Verifies token creation happens before sending.
    /// Per OpenID Connect, logout token must be created before transmission.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_ShouldCreateTokenBeforeSending()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();
        var callOrder = new System.Collections.Generic.List<string>();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .Callback(() => callOrder.Add("create"))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()))
            .Callback(() => callOrder.Add("send"))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.Equal(new[] { "create", "send" }, callOrder);
    }

    /// <summary>
    /// Verifies correct logout token is passed to sender.
    /// The token created by token service must be sent to the client.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_ShouldPassCreatedTokenToSender()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();

        EncodedJsonWebToken? capturedToken = null;

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()))
            .Callback<ClientInfo, EncodedJsonWebToken>((_, t) => capturedToken = t)
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.Same(logoutToken, capturedToken);
    }

    /// <summary>
    /// Verifies handling of different session IDs.
    /// Logout context with different session IDs should be processed correctly.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithDifferentSessionId_ShouldWork()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext(sessionId: "different_session_456");
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(
                It.Is<ClientInfo>(c => c == clientInfo),
                It.Is<LogoutContext>(lc => lc.SessionId == "different_session_456")),
            Times.Once);
    }

    /// <summary>
    /// Verifies handling of different subject IDs.
    /// Logout context with different subject IDs should be processed correctly.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithDifferentSubjectId_ShouldWork()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext(subjectId: "different_user_789");
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(
                It.Is<ClientInfo>(c => c == clientInfo),
                It.Is<LogoutContext>(lc => lc.SubjectId == "different_user_789")),
            Times.Once);
    }

    /// <summary>
    /// Verifies handling of different issuers.
    /// Logout context with different issuers should be processed correctly.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithDifferentIssuer_ShouldWork()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext(issuer: "https://different.issuer.com");
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(
                It.Is<ClientInfo>(c => c == clientInfo),
                It.Is<LogoutContext>(lc => lc.Issuer == "https://different.issuer.com")),
            Times.Once);
    }

    /// <summary>
    /// Verifies handling of different back-channel logout URIs.
    /// Clients with different logout URIs should be notified correctly.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithDifferentLogoutUri_ShouldWork()
    {
        // Arrange
        var logoutUri = new Uri("https://different.client.com/logout");
        var backChannelLogout = new BackChannelLogoutOptions(logoutUri, RequiresSessionId: true);
        var clientInfo = CreateClientInfo(backChannelLogout);
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.Equal(logoutUri, clientInfo.BackChannelLogout!.Uri);
        _logoutTokenSender.Verify(
            s => s.SendBackChannelLogoutAsync(
                It.Is<ClientInfo>(c => c.BackChannelLogout!.Uri == logoutUri),
                It.IsAny<EncodedJsonWebToken>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies handling when RequiresSessionId is false.
    /// Back-channel logout should work regardless of session requirement.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithRequiresSessionIdFalse_ShouldWork()
    {
        // Arrange
        var backChannelLogout = new BackChannelLogoutOptions(
            new Uri("https://client.example.com/backchannel_logout"),
            RequiresSessionId: false);
        var clientInfo = CreateClientInfo(backChannelLogout);
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.False(clientInfo.BackChannelLogout!.RequiresSessionId);
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()),
            Times.Once);
        _logoutTokenSender.Verify(
            s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies exception from token service is propagated.
    /// Per defensive programming, exceptions should not be swallowed.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WhenTokenServiceThrows_ShouldPropagateException()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext();
        var exception = new InvalidOperationException("Token creation failed");

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .ThrowsAsync(exception);

        // Act & Assert
        var thrownException = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _notifier.NotifyClientAsync(clientInfo, logoutContext));

        Assert.Same(exception, thrownException);
        _logoutTokenSender.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies exception from token sender is propagated.
    /// Per defensive programming, exceptions should not be swallowed.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WhenTokenSenderThrows_ShouldPropagateException()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();
        var exception = new InvalidOperationException("Token sending failed");

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()))
            .ThrowsAsync(exception);

        // Act & Assert
        var thrownException = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _notifier.NotifyClientAsync(clientInfo, logoutContext));

        Assert.Same(exception, thrownException);
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies handling of HttpRequestException from token sender.
    /// Network errors during token sending should be propagated.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WhenSenderThrowsHttpException_ShouldPropagateException()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();
        var exception = new System.Net.Http.HttpRequestException("Network error");

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()))
            .ThrowsAsync(exception);

        // Act & Assert
        await Assert.ThrowsAsync<System.Net.Http.HttpRequestException>(
            () => _notifier.NotifyClientAsync(clientInfo, logoutContext));
    }

    /// <summary>
    /// Verifies handling of TaskCanceledException from dependencies.
    /// Timeout or cancellation should be propagated.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WhenOperationCanceled_ShouldPropagateException()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext();
        var exception = new TaskCanceledException("Operation canceled");

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .ThrowsAsync(exception);

        // Act & Assert
        await Assert.ThrowsAsync<TaskCanceledException>(
            () => _notifier.NotifyClientAsync(clientInfo, logoutContext));
    }

    /// <summary>
    /// Verifies multiple sequential calls work correctly.
    /// Notifier should handle multiple logout events for different contexts.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_MultipleSequentialCalls_ShouldWork()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext1 = CreateLogoutContext(sessionId: "session_1", subjectId: "user_1");
        var logoutContext2 = CreateLogoutContext(sessionId: "session_2", subjectId: "user_2");
        var logoutToken1 = CreateLogoutToken();
        var logoutToken2 = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext1))
            .ReturnsAsync(logoutToken1);
        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext2))
            .ReturnsAsync(logoutToken2);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken1))
            .Returns(Task.CompletedTask);
        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken2))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext1);
        await _notifier.NotifyClientAsync(clientInfo, logoutContext2);

        // Assert
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(clientInfo, logoutContext1),
            Times.Once);
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(clientInfo, logoutContext2),
            Times.Once);
        _logoutTokenSender.Verify(
            s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken1),
            Times.Once);
        _logoutTokenSender.Verify(
            s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken2),
            Times.Once);
    }

    /// <summary>
    /// Verifies multiple calls for different clients work correctly.
    /// Notifier should handle logout events for multiple clients.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_ForDifferentClients_ShouldWork()
    {
        // Arrange
        var clientInfo1 = new ClientInfo("client_1")
        {
            BackChannelLogout = new BackChannelLogoutOptions(
                new Uri("https://client1.example.com/logout"),
                RequiresSessionId: true)
        };
        var clientInfo2 = new ClientInfo("client_2")
        {
            BackChannelLogout = new BackChannelLogoutOptions(
                new Uri("https://client2.example.com/logout"),
                RequiresSessionId: false)
        };
        var logoutContext = CreateLogoutContext();
        var logoutToken1 = CreateLogoutToken();
        var logoutToken2 = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo1, logoutContext))
            .ReturnsAsync(logoutToken1);
        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo2, logoutContext))
            .ReturnsAsync(logoutToken2);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo1, logoutToken1))
            .Returns(Task.CompletedTask);
        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo2, logoutToken2))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo1, logoutContext);
        await _notifier.NotifyClientAsync(clientInfo2, logoutContext);

        // Assert
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()),
            Times.Exactly(2));
        _logoutTokenSender.Verify(
            s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()),
            Times.Exactly(2));
    }

    /// <summary>
    /// Verifies empty session ID is handled correctly.
    /// Per OpenID Connect, session ID may be empty in some scenarios.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithEmptySessionId_ShouldWork()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext(sessionId: string.Empty);
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(
                It.IsAny<ClientInfo>(),
                It.Is<LogoutContext>(lc => lc.SessionId == string.Empty)),
            Times.Once);
    }

    /// <summary>
    /// Verifies empty subject ID is handled correctly.
    /// Edge case for logout context validation.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithEmptySubjectId_ShouldWork()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext(subjectId: string.Empty);
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(
                It.IsAny<ClientInfo>(),
                It.Is<LogoutContext>(lc => lc.SubjectId == string.Empty)),
            Times.Once);
    }

    /// <summary>
    /// Verifies LogoutContext with front-channel URIs is handled correctly.
    /// Back-channel notifier should ignore front-channel URIs.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithFrontChannelUris_ShouldIgnoreThem()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext();
        logoutContext.FrontChannelLogoutRequestUris.Add(new Uri("https://front.example.com/logout"));
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()),
            Times.Once);
        _logoutTokenSender.Verify(
            s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()),
            Times.Once);
        // Front-channel URIs should not affect back-channel notification
    }

    /// <summary>
    /// Verifies async behavior completes properly.
    /// All async operations should complete successfully.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_ShouldCompleteAsynchronously()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();
        var tcs = new TaskCompletionSource<EncodedJsonWebToken>();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()))
            .Returns(tcs.Task);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()))
            .Returns(Task.CompletedTask);

        // Act
        var notifyTask = _notifier.NotifyClientAsync(clientInfo, logoutContext);
        Assert.False(notifyTask.IsCompleted);

        tcs.SetResult(logoutToken);
        await notifyTask;

        // Assert
        Assert.True(notifyTask.IsCompleted);
    }

    /// <summary>
    /// Verifies very long session ID is handled correctly.
    /// Edge case for session identifier length.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithVeryLongSessionId_ShouldWork()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var longSessionId = new string('a', 1000);
        var logoutContext = CreateLogoutContext(sessionId: longSessionId);
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(
                It.IsAny<ClientInfo>(),
                It.Is<LogoutContext>(lc => lc.SessionId.Length == 1000)),
            Times.Once);
    }

    /// <summary>
    /// Verifies special characters in session ID are handled correctly.
    /// Session IDs may contain various characters.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithSpecialCharactersInSessionId_ShouldWork()
    {
        // Arrange
        var clientInfo = CreateClientInfoWithBackChannelLogout();
        var sessionId = "session-123_456.789~abc";
        var logoutContext = CreateLogoutContext(sessionId: sessionId);
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(
                It.IsAny<ClientInfo>(),
                It.Is<LogoutContext>(lc => lc.SessionId == sessionId)),
            Times.Once);
    }

    /// <summary>
    /// Verifies HTTPS requirement for logout URI.
    /// Per OpenID Connect security requirements, logout URIs should use HTTPS.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithHttpsUri_ShouldWork()
    {
        // Arrange
        var httpsUri = new Uri("https://secure.client.com/logout");
        var backChannelLogout = new BackChannelLogoutOptions(httpsUri, RequiresSessionId: true);
        var clientInfo = CreateClientInfo(backChannelLogout);
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.Equal("https", clientInfo.BackChannelLogout!.Uri.Scheme);
        _logoutTokenSender.Verify(
            s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies URI with query parameters is handled correctly.
    /// Logout URIs may contain query parameters.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithQueryParametersInUri_ShouldWork()
    {
        // Arrange
        var uriWithQuery = new Uri("https://client.example.com/logout?param=value");
        var backChannelLogout = new BackChannelLogoutOptions(uriWithQuery, RequiresSessionId: true);
        var clientInfo = CreateClientInfo(backChannelLogout);
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.Contains("param=value", clientInfo.BackChannelLogout!.Uri.Query);
        _logoutTokenSender.Verify(
            s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies URI with fragment is handled correctly.
    /// Logout URIs may contain fragments.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithFragmentInUri_ShouldWork()
    {
        // Arrange
        var uriWithFragment = new Uri("https://client.example.com/logout#section");
        var backChannelLogout = new BackChannelLogoutOptions(uriWithFragment, RequiresSessionId: true);
        var clientInfo = CreateClientInfo(backChannelLogout);
        var logoutContext = CreateLogoutContext();
        var logoutToken = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo, logoutContext))
            .ReturnsAsync(logoutToken);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo, logoutToken))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo, logoutContext);

        // Assert
        Assert.Equal("#section", clientInfo.BackChannelLogout!.Uri.Fragment);
        _logoutTokenSender.Verify(
            s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies different client IDs are handled correctly.
    /// Each client should be identified by its unique ID.
    /// </summary>
    [Fact]
    public async Task NotifyClientAsync_WithDifferentClientIds_ShouldWork()
    {
        // Arrange
        var clientInfo1 = new ClientInfo("client_abc_123")
        {
            BackChannelLogout = new BackChannelLogoutOptions(
                new Uri("https://client.example.com/logout"),
                RequiresSessionId: true)
        };
        var clientInfo2 = new ClientInfo("client_xyz_789")
        {
            BackChannelLogout = new BackChannelLogoutOptions(
                new Uri("https://client.example.com/logout"),
                RequiresSessionId: true)
        };
        var logoutContext = CreateLogoutContext();
        var logoutToken1 = CreateLogoutToken();
        var logoutToken2 = CreateLogoutToken();

        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo1, logoutContext))
            .ReturnsAsync(logoutToken1);
        _logoutTokenService
            .Setup(s => s.CreateLogoutTokenAsync(clientInfo2, logoutContext))
            .ReturnsAsync(logoutToken2);

        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo1, logoutToken1))
            .Returns(Task.CompletedTask);
        _logoutTokenSender
            .Setup(s => s.SendBackChannelLogoutAsync(clientInfo2, logoutToken2))
            .Returns(Task.CompletedTask);

        // Act
        await _notifier.NotifyClientAsync(clientInfo1, logoutContext);
        await _notifier.NotifyClientAsync(clientInfo2, logoutContext);

        // Assert
        Assert.NotEqual(clientInfo1.ClientId, clientInfo2.ClientId);
        _logoutTokenService.Verify(
            s => s.CreateLogoutTokenAsync(It.IsAny<ClientInfo>(), It.IsAny<LogoutContext>()),
            Times.Exactly(2));
        _logoutTokenSender.Verify(
            s => s.SendBackChannelLogoutAsync(It.IsAny<ClientInfo>(), It.IsAny<EncodedJsonWebToken>()),
            Times.Exactly(2));
    }
}
