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
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

/// <summary>
/// Unit tests for <see cref="HttpBackChannelNotificationService"/> verifying CIBA ping mode
/// HTTP notification functionality as defined in the OpenID Connect CIBA specification Section 10.2.
/// Tests cover successful notifications, error handling, authentication, and payload validation.
/// </summary>
public class HttpBackChannelNotificationServiceTests
{
    private const string AuthReqId = "auth_req_abc123";
    private const string ClientNotificationToken = "bearer_token_xyz";
    private readonly Uri _clientNotificationEndpoint = new("https://client.example.com/ciba/notify");

    private readonly Mock<IHttpClientFactory> _httpClientFactory;
    private readonly Mock<ILogger<HttpBackChannelNotificationService>> _logger;
    private readonly HttpBackChannelNotificationService _service;

    public HttpBackChannelNotificationServiceTests()
    {
        _httpClientFactory = new Mock<IHttpClientFactory>(MockBehavior.Strict);
        _logger = new Mock<ILogger<HttpBackChannelNotificationService>>(MockBehavior.Loose);
        _service = new HttpBackChannelNotificationService(_httpClientFactory.Object, _logger.Object);
    }

    /// <summary>
    /// Verifies that a successful notification sends the correct HTTP POST request
    /// with proper authentication and payload according to CIBA spec Section 10.2.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_Success_SendsCorrectHttpRequest()
    {
        // Arrange
        HttpRequestMessage? capturedRequest = null;
        var mockHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedRequest = req)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var httpClient = new HttpClient(mockHandler.Object);
        _httpClientFactory.Setup(f => f.CreateClient(nameof(HttpBackChannelNotificationService)))
            .Returns(httpClient);

        // Act
        await _service.NotifyAsync(_clientNotificationEndpoint, ClientNotificationToken, AuthReqId);

        // Assert
        Assert.NotNull(capturedRequest);
        Assert.Equal(HttpMethod.Post, capturedRequest.Method);
        Assert.Equal(_clientNotificationEndpoint, capturedRequest.RequestUri);
        Assert.Contains(capturedRequest.Headers.GetValues("Authorization"),
            h => h == $"Bearer {ClientNotificationToken}");

        // Verify payload
        var content = await capturedRequest.Content!.ReadAsStringAsync();
        var payload = JsonSerializer.Deserialize<JsonElement>(content);
        Assert.Equal(AuthReqId, payload.GetProperty("authenticationRequestId").GetString());
    }

    /// <summary>
    /// Verifies that when the notification endpoint returns a success status code,
    /// the service logs the success appropriately.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_SuccessResponse_LogsSuccess()
    {
        // Arrange
        var mockHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.NoContent));

        var httpClient = new HttpClient(mockHandler.Object);
        _httpClientFactory.Setup(f => f.CreateClient(nameof(HttpBackChannelNotificationService)))
            .Returns(httpClient);

        // Act
        await _service.NotifyAsync(_clientNotificationEndpoint, ClientNotificationToken, AuthReqId);

        // Assert
        _logger.Verify(
            l => l.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("Successfully sent CIBA ping notification")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that when the notification endpoint returns an error status code,
    /// the service logs a warning with the status code but does not throw.
    /// The CIBA spec recommends best-effort delivery for ping notifications.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_ErrorResponse_LogsWarningAndDoesNotThrow()
    {
        // Arrange
        var mockHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.BadRequest));

        var httpClient = new HttpClient(mockHandler.Object);
        _httpClientFactory.Setup(f => f.CreateClient(nameof(HttpBackChannelNotificationService)))
            .Returns(httpClient);

        // Act & Assert (should not throw)
        await _service.NotifyAsync(_clientNotificationEndpoint, ClientNotificationToken, AuthReqId);

        _logger.Verify(
            l => l.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("Failed to send CIBA ping notification")),
                null,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that when an exception occurs during notification,
    /// the service logs the error but does not propagate the exception.
    /// This ensures that notification failures don't break the authentication flow.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_HttpException_LogsErrorAndDoesNotThrow()
    {
        // Arrange
        var expectedException = new HttpRequestException("Network error");
        var mockHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(expectedException);

        var httpClient = new HttpClient(mockHandler.Object);
        _httpClientFactory.Setup(f => f.CreateClient(nameof(HttpBackChannelNotificationService)))
            .Returns(httpClient);

        // Act & Assert (should not throw)
        await _service.NotifyAsync(_clientNotificationEndpoint, ClientNotificationToken, AuthReqId);

        _logger.Verify(
            l => l.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString()!.Contains("Error sending CIBA ping notification")),
                expectedException,
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that the notification request includes the correct Authorization header
    /// with Bearer token authentication as required by CIBA spec.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_IncludesAuthorizationHeader()
    {
        // Arrange
        HttpRequestMessage? capturedRequest = null;
        var mockHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedRequest = req)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var httpClient = new HttpClient(mockHandler.Object);
        _httpClientFactory.Setup(f => f.CreateClient(nameof(HttpBackChannelNotificationService)))
            .Returns(httpClient);

        // Act
        await _service.NotifyAsync(_clientNotificationEndpoint, ClientNotificationToken, AuthReqId);

        // Assert
        Assert.NotNull(capturedRequest);
        Assert.True(capturedRequest.Headers.Contains("Authorization"));
        var authHeader = string.Join("", capturedRequest.Headers.GetValues("Authorization"));
        Assert.Equal($"Bearer {ClientNotificationToken}", authHeader);
    }

    /// <summary>
    /// Verifies that the notification uses the HTTP client factory with the correct client name,
    /// ensuring proper configuration and handler lifetime management.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_UsesCorrectHttpClientName()
    {
        // Arrange
        var mockHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var httpClient = new HttpClient(mockHandler.Object);
        _httpClientFactory.Setup(f => f.CreateClient(nameof(HttpBackChannelNotificationService)))
            .Returns(httpClient);

        // Act
        await _service.NotifyAsync(_clientNotificationEndpoint, ClientNotificationToken, AuthReqId);

        // Assert
        _httpClientFactory.Verify(
            f => f.CreateClient(nameof(HttpBackChannelNotificationService)),
            Times.Once);
    }

    /// <summary>
    /// Verifies that the notification payload contains exactly the auth_req_id parameter
    /// as specified in CIBA spec Section 10.2.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_PayloadContainsAuthReqId()
    {
        // Arrange
        string? capturedContent = null;
        var mockHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>(async (req, _) =>
                capturedContent = await req.Content!.ReadAsStringAsync())
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var httpClient = new HttpClient(mockHandler.Object);
        _httpClientFactory.Setup(f => f.CreateClient(nameof(HttpBackChannelNotificationService)))
            .Returns(httpClient);

        // Act
        await _service.NotifyAsync(_clientNotificationEndpoint, ClientNotificationToken, AuthReqId);

        // Assert
        Assert.NotNull(capturedContent);
        var payload = JsonSerializer.Deserialize<JsonElement>(capturedContent);
        Assert.True(payload.TryGetProperty("authenticationRequestId", out var authReqIdProperty));
        Assert.Equal(AuthReqId, authReqIdProperty.GetString());
    }

    /// <summary>
    /// Verifies that the notification request uses JSON content type.
    /// </summary>
    [Fact]
    public async Task NotifyAsync_UsesJsonContentType()
    {
        // Arrange
        HttpRequestMessage? capturedRequest = null;
        var mockHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedRequest = req)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var httpClient = new HttpClient(mockHandler.Object);
        _httpClientFactory.Setup(f => f.CreateClient(nameof(HttpBackChannelNotificationService)))
            .Returns(httpClient);

        // Act
        await _service.NotifyAsync(_clientNotificationEndpoint, ClientNotificationToken, AuthReqId);

        // Assert
        Assert.NotNull(capturedRequest?.Content);
        Assert.Equal("application/json", capturedRequest.Content.Headers.ContentType?.MediaType);
    }
}
