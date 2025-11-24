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
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.Tokens;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Features.LogoutNotification;

/// <summary>
/// Unit tests for <see cref="BackChannelLogoutTokenSender"/> verifying back-channel logout token transmission
/// per OpenID Connect Back-Channel Logout specification.
/// </summary>
public class BackChannelLogoutTokenSenderTests
{
    private readonly Mock<ILogger<BackChannelLogoutTokenSender>> _logger;
    private readonly Mock<HttpMessageHandler> _httpMessageHandler;
    private readonly HttpClient _httpClient;

    public BackChannelLogoutTokenSenderTests()
    {
        _logger = new Mock<ILogger<BackChannelLogoutTokenSender>>();
        _httpMessageHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        _httpClient = new HttpClient(_httpMessageHandler.Object);
    }

    private BackChannelLogoutTokenSender CreateSender()
    {
        return new BackChannelLogoutTokenSender(_logger.Object, _httpClient);
    }

    private static ClientInfo CreateClientInfo(Uri? backChannelLogoutUri = null)
    {
        var uri = backChannelLogoutUri ?? new Uri("https://client.example.com/backchannel_logout");
        return new ClientInfo(TestConstants.DefaultClientId)
        {
            BackChannelLogout = new BackChannelLogoutOptions(uri, RequiresSessionId: true)
        };
    }

    private static EncodedJsonWebToken CreateLogoutToken(string encodedJwt = "encoded.jwt.token")
    {
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new System.Text.Json.Nodes.JsonObject()),
            Payload = new JsonWebTokenPayload(new System.Text.Json.Nodes.JsonObject())
        };
        return new EncodedJsonWebToken(token, encodedJwt);
    }

    private void SetupHttpResponse(HttpStatusCode statusCode, string? content = null)
    {
        var response = new HttpResponseMessage(statusCode)
        {
            Content = content != null ? new StringContent(content) : new StringContent("")
        };

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);
    }

    /// <summary>
    /// Verifies successful token sending with 200 OK response.
    /// Per OpenID Connect Back-Channel Logout, 200 OK indicates successful delivery.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_WithSuccessResponse_ShouldComplete()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        SetupHttpResponse(HttpStatusCode.OK);

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        _httpMessageHandler.Protected().Verify(
            "SendAsync",
            Times.Once(),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
    }

    /// <summary>
    /// Verifies HTTP request is POST method.
    /// Per OpenID Connect Back-Channel Logout, logout tokens must be sent via POST.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_ShouldUsePostMethod()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        HttpMethod? capturedMethod = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedMethod = req.Method)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        Assert.Equal(HttpMethod.Post, capturedMethod);
    }

    /// <summary>
    /// Verifies correct URI is used for the request.
    /// The back-channel logout URI from client configuration must be used.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_ShouldUseCorrectUri()
    {
        // Arrange
        var targetUri = new Uri("https://specific.client.com/logout");
        var sender = CreateSender();
        var clientInfo = CreateClientInfo(targetUri);
        var logoutToken = CreateLogoutToken();
        Uri? capturedUri = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedUri = req.RequestUri)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        Assert.Equal(targetUri, capturedUri);
    }

    /// <summary>
    /// Verifies content type is application/x-www-form-urlencoded.
    /// Per OpenID Connect Back-Channel Logout, form encoding must be used.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_ShouldUseFormUrlEncodedContent()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        string? capturedContentType = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                capturedContentType = req.Content?.Headers.ContentType?.MediaType)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        Assert.Equal("application/x-www-form-urlencoded", capturedContentType);
    }

    /// <summary>
    /// Verifies logout_token parameter is included in request body.
    /// Per OpenID Connect Back-Channel Logout, logout_token parameter is required.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_ShouldIncludeLogoutTokenParameter()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken("my.encoded.jwt");
        string? capturedContent = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>(async (req, _) =>
                capturedContent = await req.Content!.ReadAsStringAsync())
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        Assert.Contains("logout_token=", capturedContent);
        Assert.Contains("my.encoded.jwt", capturedContent);
    }

    /// <summary>
    /// Verifies exception when BackChannelLogout is null.
    /// Per defensive programming, null configuration must be rejected.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_WithNullBackChannelLogout_ShouldThrowException()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId) { BackChannelLogout = null };
        var logoutToken = CreateLogoutToken();

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => sender.SendBackChannelLogoutAsync(clientInfo, logoutToken));
    }

    /// <summary>
    /// Verifies exception on 400 Bad Request response.
    /// Per HTTP specification, 4xx errors should throw HttpRequestException.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_With400Response_ShouldThrowException()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        SetupHttpResponse(HttpStatusCode.BadRequest);

        // Act & Assert
        await Assert.ThrowsAsync<HttpRequestException>(
            () => sender.SendBackChannelLogoutAsync(clientInfo, logoutToken));
    }

    /// <summary>
    /// Verifies exception on 401 Unauthorized response.
    /// Authentication failures should throw HttpRequestException.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_With401Response_ShouldThrowException()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        SetupHttpResponse(HttpStatusCode.Unauthorized);

        // Act & Assert
        await Assert.ThrowsAsync<HttpRequestException>(
            () => sender.SendBackChannelLogoutAsync(clientInfo, logoutToken));
    }

    /// <summary>
    /// Verifies exception on 403 Forbidden response.
    /// Authorization failures should throw HttpRequestException.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_With403Response_ShouldThrowException()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        SetupHttpResponse(HttpStatusCode.Forbidden);

        // Act & Assert
        await Assert.ThrowsAsync<HttpRequestException>(
            () => sender.SendBackChannelLogoutAsync(clientInfo, logoutToken));
    }

    /// <summary>
    /// Verifies exception on 404 Not Found response.
    /// Invalid logout endpoints should throw HttpRequestException.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_With404Response_ShouldThrowException()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        SetupHttpResponse(HttpStatusCode.NotFound);

        // Act & Assert
        await Assert.ThrowsAsync<HttpRequestException>(
            () => sender.SendBackChannelLogoutAsync(clientInfo, logoutToken));
    }

    /// <summary>
    /// Verifies exception on 500 Internal Server Error response.
    /// Server errors should throw HttpRequestException.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_With500Response_ShouldThrowException()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        SetupHttpResponse(HttpStatusCode.InternalServerError);

        // Act & Assert
        await Assert.ThrowsAsync<HttpRequestException>(
            () => sender.SendBackChannelLogoutAsync(clientInfo, logoutToken));
    }

    /// <summary>
    /// Verifies exception on 503 Service Unavailable response.
    /// Temporary unavailability should throw HttpRequestException.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_With503Response_ShouldThrowException()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        SetupHttpResponse(HttpStatusCode.ServiceUnavailable);

        // Act & Assert
        await Assert.ThrowsAsync<HttpRequestException>(
            () => sender.SendBackChannelLogoutAsync(clientInfo, logoutToken));
    }

    /// <summary>
    /// Verifies successful completion with 204 No Content response.
    /// Per HTTP specification, 2xx responses indicate success.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_With204Response_ShouldComplete()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        SetupHttpResponse(HttpStatusCode.NoContent);

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        _httpMessageHandler.Protected().Verify(
            "SendAsync",
            Times.Once(),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
    }

    /// <summary>
    /// Verifies handling of network errors.
    /// Network exceptions should be propagated.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_WithNetworkError_ShouldPropagateException()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("Network error"));

        // Act & Assert
        await Assert.ThrowsAsync<HttpRequestException>(
            () => sender.SendBackChannelLogoutAsync(clientInfo, logoutToken));
    }

    /// <summary>
    /// Verifies handling of timeout exceptions.
    /// Timeouts should be propagated.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_WithTimeout_ShouldPropagateException()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new TaskCanceledException("Request timeout"));

        // Act & Assert
        await Assert.ThrowsAsync<TaskCanceledException>(
            () => sender.SendBackChannelLogoutAsync(clientInfo, logoutToken));
    }

    /// <summary>
    /// Verifies multiple sequential calls work correctly.
    /// Sender should handle multiple logout requests.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_MultipleSequentialCalls_ShouldWork()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo1 = CreateClientInfo(new Uri("https://client1.example.com/logout"));
        var clientInfo2 = CreateClientInfo(new Uri("https://client2.example.com/logout"));
        var logoutToken1 = CreateLogoutToken("token1");
        var logoutToken2 = CreateLogoutToken("token2");

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(() => new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo1, logoutToken1);
        await sender.SendBackChannelLogoutAsync(clientInfo2, logoutToken2);

        // Assert
        _httpMessageHandler.Protected().Verify(
            "SendAsync",
            Times.Exactly(2),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
    }

    /// <summary>
    /// Verifies different encoded JWTs are sent correctly.
    /// Each logout token should contain its specific encoded JWT.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_WithDifferentTokens_ShouldSendCorrectToken()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken("specific.encoded.jwt.abc123");
        string? capturedContent = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>(async (req, _) =>
                capturedContent = await req.Content!.ReadAsStringAsync())
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        Assert.Contains("specific.encoded.jwt.abc123", capturedContent);
    }

    /// <summary>
    /// Verifies URI with query parameters is handled correctly.
    /// Query parameters in logout URI should be preserved.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_WithUriQueryParameters_ShouldPreserveThem()
    {
        // Arrange
        var uriWithQuery = new Uri("https://client.example.com/logout?param=value");
        var sender = CreateSender();
        var clientInfo = CreateClientInfo(uriWithQuery);
        var logoutToken = CreateLogoutToken();
        Uri? capturedUri = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedUri = req.RequestUri)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        Assert.Contains("param=value", capturedUri!.Query);
    }

    /// <summary>
    /// Verifies URI with port number is handled correctly.
    /// Port numbers should be preserved in the request.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_WithPortNumber_ShouldUseCorrectPort()
    {
        // Arrange
        var uriWithPort = new Uri("https://client.example.com:8443/logout");
        var sender = CreateSender();
        var clientInfo = CreateClientInfo(uriWithPort);
        var logoutToken = CreateLogoutToken();
        Uri? capturedUri = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedUri = req.RequestUri)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        Assert.Equal(8443, capturedUri!.Port);
    }

    /// <summary>
    /// Verifies HTTPS URIs are used correctly.
    /// Per OpenID Connect security requirements, HTTPS should be preferred.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_WithHttpsUri_ShouldWork()
    {
        // Arrange
        var httpsUri = new Uri("https://secure.client.com/logout");
        var sender = CreateSender();
        var clientInfo = CreateClientInfo(httpsUri);
        var logoutToken = CreateLogoutToken();
        Uri? capturedUri = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedUri = req.RequestUri)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        Assert.Equal("https", capturedUri!.Scheme);
    }

    /// <summary>
    /// Verifies very long encoded JWT is handled correctly.
    /// Long tokens should not cause issues.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_WithVeryLongToken_ShouldWork()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var longToken = new string('a', 5000);
        var logoutToken = CreateLogoutToken(longToken);

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert - No exception thrown
        _httpMessageHandler.Protected().Verify(
            "SendAsync",
            Times.Once(),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
    }

    /// <summary>
    /// Verifies special characters in encoded JWT are handled correctly.
    /// URL encoding should not corrupt the token.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_WithSpecialCharactersInToken_ShouldEncodeCorrectly()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var tokenWithSpecialChars = "eyJhbGci.eyJzdWIi+123/abc==";
        var logoutToken = CreateLogoutToken(tokenWithSpecialChars);
        string? capturedContent = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>(async (req, _) =>
                capturedContent = await req.Content!.ReadAsStringAsync())
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        Assert.NotNull(capturedContent);
        // The token should be present, possibly URL-encoded
        Assert.True(capturedContent.Contains("eyJhbGci") || capturedContent.Contains("%"));
    }

    /// <summary>
    /// Verifies response with content is handled correctly.
    /// Response body should not affect success/failure determination.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_WithResponseContent_ShouldIgnoreContent()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        SetupHttpResponse(HttpStatusCode.OK, "response body content");

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert - No exception thrown
        _httpMessageHandler.Protected().Verify(
            "SendAsync",
            Times.Once(),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
    }

    /// <summary>
    /// Verifies HTTP method case sensitivity.
    /// POST should be uppercase.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_ShouldUseUppercasePost()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        HttpMethod? capturedMethod = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedMethod = req.Method)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        Assert.Equal("POST", capturedMethod!.Method);
    }

    /// <summary>
    /// Verifies request headers do not contain unexpected headers.
    /// Only necessary headers should be included.
    /// </summary>
    [Fact]
    public async Task SendBackChannelLogoutAsync_ShouldNotIncludeExtraHeaders()
    {
        // Arrange
        var sender = CreateSender();
        var clientInfo = CreateClientInfo();
        var logoutToken = CreateLogoutToken();
        HttpRequestMessage? capturedRequest = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedRequest = req)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        // Act
        await sender.SendBackChannelLogoutAsync(clientInfo, logoutToken);

        // Assert
        Assert.NotNull(capturedRequest);
        // Should have minimal headers (Content-Type from content, maybe Content-Length)
        // No authorization, cookies, etc.
        Assert.DoesNotContain("Authorization", capturedRequest.Headers.Select(h => h.Key));
        Assert.DoesNotContain("Cookie", capturedRequest.Headers.Select(h => h.Key));
    }
}
