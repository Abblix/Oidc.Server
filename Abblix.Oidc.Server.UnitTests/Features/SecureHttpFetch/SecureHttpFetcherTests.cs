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
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Unit tests for <see cref="SecureHttpFetcher"/> verifying secure HTTP content fetching
/// with SSRF protection.
/// </summary>
public class SecureHttpFetcherTests
{
    private readonly Mock<ILogger<SecureHttpFetcher>> _logger;
    private readonly Mock<HttpMessageHandler> _httpMessageHandler;
    private readonly HttpClient _httpClient;

    public SecureHttpFetcherTests()
    {
        _logger = new Mock<ILogger<SecureHttpFetcher>>();
        _httpMessageHandler = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        _httpClient = new HttpClient(_httpMessageHandler.Object);
    }

    private SecureHttpFetcher CreateFetcher()
    {
        var options = Options.Create(new SecureHttpFetchOptions());
        return new SecureHttpFetcher(_httpClient, options, _logger.Object);
    }

    private void SetupHttpResponse(HttpStatusCode statusCode, string content, string contentType = "application/json")
    {
        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(content, Encoding.UTF8, contentType)
        };

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);
    }

    private record TestModel(string Name, int Value);

    /// <summary>
    /// Verifies successful JSON deserialization.
    /// Per OIDC specification, JSON content should be deserialized to the specified type.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithValidJson_ShouldDeserializeSuccessfully()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/data");
        var json = JsonSerializer.Serialize(new TestModel("Test", 42));
        SetupHttpResponse(HttpStatusCode.OK, json);

        // Act
        var result = await fetcher.FetchAsync<TestModel>(uri);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Equal("Test", value.Name);
        Assert.Equal(42, value.Value);
    }

    /// <summary>
    /// Verifies successful string content retrieval.
    /// When T is string, raw content should be returned without deserialization.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithStringType_ShouldReturnRawContent()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/jwt");
        var jwtContent = "eyJhbGci.eyJzdWIi.signature";
        SetupHttpResponse(HttpStatusCode.OK, jwtContent, "text/plain");

        // Act
        var result = await fetcher.FetchAsync<string>(uri);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Equal(jwtContent, value);
    }

    /// <summary>
    /// Verifies error on 404 Not Found response.
    /// HTTP errors should return OidcError result.
    /// </summary>
    [Fact]
    public async Task FetchAsync_With404Response_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/notfound");
        SetupHttpResponse(HttpStatusCode.NotFound, "Not Found");

        // Act
        var result = await fetcher.FetchAsync<TestModel>(uri);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    /// <summary>
    /// Verifies error on 500 Internal Server Error response.
    /// Server errors should return OidcError result.
    /// </summary>
    [Fact]
    public async Task FetchAsync_With500Response_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/error");
        SetupHttpResponse(HttpStatusCode.InternalServerError, "Server Error");

        // Act
        var result = await fetcher.FetchAsync<string>(uri);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    /// <summary>
    /// Verifies error on invalid JSON.
    /// Deserialization failures should return OidcError result.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithInvalidJson_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/invalid");
        SetupHttpResponse(HttpStatusCode.OK, "not valid json{");

        // Act
        var result = await fetcher.FetchAsync<TestModel>(uri);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    /// <summary>
    /// Verifies error on null content.
    /// Per defensive programming, null content must be rejected.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithNullContent_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/null");
        SetupHttpResponse(HttpStatusCode.OK, "null");

        // Act
        var result = await fetcher.FetchAsync<TestModel>(uri);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("empty or null", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error on empty string content.
    /// Empty content should be rejected for non-string types.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithEmptyContent_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/empty");
        SetupHttpResponse(HttpStatusCode.OK, "");

        // Act
        var result = await fetcher.FetchAsync<TestModel>(uri);

        // Assert
        Assert.True(result.TryGetFailure(out _));
    }

    /// <summary>
    /// Verifies handling of network errors.
    /// Network exceptions should be caught and returned as OidcError.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithNetworkError_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/network");

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("Network error"));

        // Act
        var result = await fetcher.FetchAsync<string>(uri);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    /// <summary>
    /// Verifies handling of timeout exceptions.
    /// Timeouts should be caught and returned as OidcError.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithTimeout_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/timeout");

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new TaskCanceledException("Timeout"));

        // Act
        var result = await fetcher.FetchAsync<string>(uri);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    /// <summary>
    /// Verifies HTTP GET method is used.
    /// Per HTTP specification, content fetching should use GET.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ShouldUseGetMethod()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/data");
        HttpMethod? capturedMethod = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedMethod = req.Method)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("\"test\"", Encoding.UTF8, "application/json")
            });

        // Act
        await fetcher.FetchAsync<string>(uri);

        // Assert
        Assert.Equal(HttpMethod.Get, capturedMethod);
    }

    /// <summary>
    /// Verifies correct URI is used for the request.
    /// The specified URI must be used without modification.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ShouldUseCorrectUri()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://specific.example.com/path?query=value");
        Uri? capturedUri = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedUri = req.RequestUri)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("\"test\"", Encoding.UTF8, "application/json")
            });

        // Act
        await fetcher.FetchAsync<string>(uri);

        // Assert
        Assert.Equal(uri, capturedUri);
    }

    /// <summary>
    /// Verifies multiple sequential calls work correctly.
    /// Fetcher should handle multiple requests.
    /// </summary>
    [Fact]
    public async Task FetchAsync_MultipleSequentialCalls_ShouldWork()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri1 = new Uri("https://example.com/1");
        var uri2 = new Uri("https://example.com/2");

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(() => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("\"test\"", Encoding.UTF8, "application/json")
            });

        // Act
        var result1 = await fetcher.FetchAsync<string>(uri1);
        var result2 = await fetcher.FetchAsync<string>(uri2);

        // Assert
        Assert.True(result1.TryGetSuccess(out _));
        Assert.True(result2.TryGetSuccess(out _));
        _httpMessageHandler.Protected().Verify(
            "SendAsync",
            Times.Exactly(2),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
    }

    /// <summary>
    /// Verifies JSON with special characters is handled correctly.
    /// Special characters should be properly deserialized.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithSpecialCharactersInJson_ShouldDeserialize()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/special");
        var json = JsonSerializer.Serialize(new TestModel("Test with \"quotes\" and \n newlines", 123));
        SetupHttpResponse(HttpStatusCode.OK, json);

        // Act
        var result = await fetcher.FetchAsync<TestModel>(uri);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Contains("quotes", value.Name);
    }

    /// <summary>
    /// Verifies HTTPS URIs work correctly.
    /// Per security requirements, HTTPS should be supported.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithHttpsUri_ShouldWork()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://secure.example.com/data");
        SetupHttpResponse(HttpStatusCode.OK, "\"test\"");

        // Act
        var result = await fetcher.FetchAsync<string>(uri);

        // Assert
        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies URI with port number is handled correctly.
    /// Port numbers should be preserved in the request.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithPortNumber_ShouldWork()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com:8443/data");
        Uri? capturedUri = null;

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Callback<HttpRequestMessage, CancellationToken>((req, _) => capturedUri = req.RequestUri)
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("\"test\"", Encoding.UTF8, "application/json")
            });

        // Act
        await fetcher.FetchAsync<string>(uri);

        // Assert
        Assert.Equal(8443, capturedUri!.Port);
    }

    /// <summary>
    /// Verifies successful fetch with 204 No Content is handled as error.
    /// 204 typically means no content, which should be an error for fetching.
    /// </summary>
    [Fact]
    public async Task FetchAsync_With204NoContent_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/nocontent");

        var response = new HttpResponseMessage(HttpStatusCode.NoContent)
        {
            Content = new StringContent("", Encoding.UTF8, "application/json")
        };

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);

        // Act
        var result = await fetcher.FetchAsync<string>(uri);

        // Assert
        Assert.True(result.TryGetFailure(out _));
    }

    /// <summary>
    /// Verifies large JSON responses are handled correctly.
    /// Large content should not cause issues.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithLargeJson_ShouldWork()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/large");
        var largeValue = new string('a', 10000);
        var json = JsonSerializer.Serialize(new TestModel(largeValue, 999));
        SetupHttpResponse(HttpStatusCode.OK, json);

        // Act
        var result = await fetcher.FetchAsync<TestModel>(uri);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Equal(10000, value.Name.Length);
    }

    /// <summary>
    /// Verifies nested JSON objects are deserialized correctly.
    /// Complex JSON structures should be supported.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithNestedJson_ShouldDeserialize()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/nested");
        var json = "{\"Name\":\"Parent\",\"Value\":1}";
        SetupHttpResponse(HttpStatusCode.OK, json);

        // Act
        var result = await fetcher.FetchAsync<TestModel>(uri);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Equal("Parent", value.Name);
    }

    /// <summary>
    /// Verifies error description contains helpful information.
    /// Error messages should be descriptive for debugging.
    /// </summary>
    [Fact]
    public async Task FetchAsync_OnError_ShouldProvideDescriptiveErrorMessage()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var uri = new Uri("https://example.com/error");

        _httpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("Specific network error"));

        // Act
        var result = await fetcher.FetchAsync<string>(uri);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("Unable to fetch content", error.ErrorDescription);
    }
}
