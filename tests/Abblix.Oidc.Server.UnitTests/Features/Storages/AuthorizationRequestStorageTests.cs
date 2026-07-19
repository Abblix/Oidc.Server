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
using System.Globalization;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages;

/// <summary>
/// Unit tests for <see cref="AuthorizationRequestStorage"/> verifying authorization request
/// storage and retrieval per OAuth 2.0 Pushed Authorization Requests (PAR) specification.
/// </summary>
public class AuthorizationRequestStorageTests
{
    private readonly Mock<IAuthorizationRequestUriGenerator> _uriGenerator;
    private readonly Mock<IEntityStorage> _storage;
    private readonly Mock<IEntityStorageKeyFactory> _keyFactory;
    private readonly AuthorizationRequestStorage _requestStorage;

    public AuthorizationRequestStorageTests()
    {
        _uriGenerator = new Mock<IAuthorizationRequestUriGenerator>(MockBehavior.Strict);
        _storage = new Mock<IEntityStorage>(MockBehavior.Strict);
        _keyFactory = new Mock<IEntityStorageKeyFactory>(MockBehavior.Strict);

        // Setup key factory to return URI as key (original string)
        _keyFactory
            .Setup(kf => kf.AuthorizationRequestKey(It.IsAny<Uri>()))
            .Returns<Uri>(uri => $"Abblix.Oidc.Server:PAR:{uri.OriginalString}");

        _requestStorage = new AuthorizationRequestStorage(
            _uriGenerator.Object,
            _storage.Object,
            _keyFactory.Object);
    }

    /// <summary>
    /// Creates a minimal authorization request with required fields only.
    /// Used for testing basic functionality without optional field complexity.
    /// </summary>
    private static AuthorizationRequest CreateMinimalRequest()
    {
        return new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = ["code"],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [TestConstants.DefaultScope],
        };
    }

    /// <summary>
    /// Creates an authorization request with all optional fields populated.
    /// Used for testing complete data preservation across storage operations.
    /// </summary>
    private static AuthorizationRequest CreateCompleteRequest()
    {
        return new AuthorizationRequest
        {
            ClientId = "client_456",
            ResponseType = ["code", "id_token"],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [TestConstants.DefaultScope, "profile", "email", "offline_access"],
            State = "state_xyz",
            ResponseMode = "form_post",
            Nonce = "nonce_abc",
            Display = "page",
            Prompt = "consent",
            MaxAge = TimeSpan.FromHours(2),
            UiLocales = [CultureInfo.GetCultureInfo("en-US"), CultureInfo.GetCultureInfo("fr-FR")],
            IdTokenHint = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            LoginHint = "user@example.com",
            AcrValues = ["urn:mace:incommon:iap:silver"],
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = "S256",
        };
    }

    /// <summary>
    /// Verifies that StoreAsync generates URI from the generator.
    /// Per OAuth 2.0 PAR, each authorization request must have a unique request_uri.
    /// </summary>
    [Fact]
    public async Task StoreAsync_ShouldGenerateUriFromGenerator()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var expectedUri = new Uri("urn:ietf:params:oauth:request_uri:generated_123");

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(expectedUri);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        Assert.Equal(expectedUri, result.RequestUri);
    }

    /// <summary>
    /// Verifies that StoreAsync stores request in storage with correct key.
    /// Key must be derived from URI.OriginalString for consistent retrieval.
    /// </summary>
    [Fact]
    public async Task StoreAsync_ShouldStoreRequestWithCorrectKey()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:test_key");
        string? capturedKey = null;

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, AuthorizationRequest, StorageOptions, System.Threading.CancellationToken?>(
                (key, _, _, _) => capturedKey = key)
            .Returns(Task.CompletedTask);

        // Act
        await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        Assert.Equal($"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}", capturedKey);
    }

    /// <summary>
    /// Verifies that StoreAsync returns PushedAuthorizationResponse with request.
    /// Response must include the original request for validation purposes.
    /// </summary>
    [Fact]
    public async Task StoreAsync_ShouldReturnPushedAuthorizationResponseWithRequest()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:resp_test");

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        Assert.Same(request, result.Model);
    }

    /// <summary>
    /// Verifies that StoreAsync returns response with generated URI.
    /// Per OAuth 2.0 PAR, request_uri must be returned to client for subsequent use.
    /// </summary>
    [Fact]
    public async Task StoreAsync_ShouldReturnResponseWithGeneratedUri()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var expectedUri = new Uri("urn:ietf:params:oauth:request_uri:uri_test");

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(expectedUri);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        Assert.Equal(expectedUri, result.RequestUri);
    }

    /// <summary>
    /// Verifies that StoreAsync returns response with correct expiresIn.
    /// Per OAuth 2.0 PAR, client needs to know request expiration time.
    /// </summary>
    [Fact]
    public async Task StoreAsync_ShouldReturnResponseWithCorrectExpiresIn()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(15);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:expires_test");

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        Assert.Equal(expiresIn, result.ExpiresIn);
    }

    /// <summary>
    /// Verifies that StoreAsync uses URI.OriginalString as storage key.
    /// OriginalString preserves exact URI format for consistent key mapping.
    /// </summary>
    [Fact]
    public async Task StoreAsync_ShouldUseUriOriginalStringAsStorageKey()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:original_string_test");
        string? capturedKey = null;

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, AuthorizationRequest, StorageOptions, System.Threading.CancellationToken?>(
                (key, _, _, _) => capturedKey = key)
            .Returns(Task.CompletedTask);

        // Act
        await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        Assert.Equal($"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}", capturedKey);
    }

    /// <summary>
    /// Verifies that StoreAsync sets AbsoluteExpirationRelativeToNow in storage options.
    /// Per OAuth 2.0 PAR, requests should expire after a short period (typically 10 minutes).
    /// </summary>
    [Fact]
    public async Task StoreAsync_ShouldSetAbsoluteExpirationRelativeToNow()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:expiration_test");
        StorageOptions? capturedOptions = null;

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, AuthorizationRequest, StorageOptions, System.Threading.CancellationToken?>(
                (_, _, options, _) => capturedOptions = options)
            .Returns(Task.CompletedTask);

        // Act
        await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.Equal(expiresIn, capturedOptions!.AbsoluteExpirationRelativeToNow);
    }

    /// <summary>
    /// Verifies that StoreAsync calls URI generator exactly once.
    /// Each storage operation should generate a unique URI.
    /// </summary>
    [Fact]
    public async Task StoreAsync_ShouldCallUriGeneratorOnce()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:once_test");

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        _uriGenerator.Verify(g => g.GenerateRequestUri(), Times.Once);
    }

    /// <summary>
    /// Verifies that StoreAsync calls storage.SetAsync exactly once.
    /// Single storage call ensures efficient persistence without redundant writes.
    /// </summary>
    [Fact]
    public async Task StoreAsync_ShouldCallStorageSetAsyncOnce()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:set_once_test");

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        _storage.Verify(
            s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that multiple stores generate different URIs.
    /// Per OAuth 2.0 PAR, each authorization request must have a unique request_uri.
    /// </summary>
    [Fact]
    public async Task StoreAsync_MultipleCalls_ShouldGenerateDifferentUris()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);

        _uriGenerator
            .SetupSequence(g => g.GenerateRequestUri())
            .Returns(new Uri("urn:ietf:params:oauth:request_uri:first"))
            .Returns(new Uri("urn:ietf:params:oauth:request_uri:second"))
            .Returns(new Uri("urn:ietf:params:oauth:request_uri:third"));

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        // Act
        var result1 = await _requestStorage.StoreAsync(request, expiresIn);
        var result2 = await _requestStorage.StoreAsync(request, expiresIn);
        var result3 = await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        Assert.NotEqual(result1.RequestUri, result2.RequestUri);
        Assert.NotEqual(result2.RequestUri, result3.RequestUri);
        Assert.NotEqual(result1.RequestUri, result3.RequestUri);
    }

    /// <summary>
    /// Verifies that TryGetAsync returns stored request for valid URI.
    /// Per OAuth 2.0 PAR, valid request_uri should return the stored authorization request.
    /// </summary>
    [Fact]
    public async Task TryGetAsync_WithValidUri_ShouldReturnStoredRequest()
    {
        // Arrange
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:valid_get");
        var expectedRequest = CreateMinimalRequest();

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(expectedRequest);

        // Act
        var result = await _requestStorage.TryGetAsync(requestUri);

        // Assert
        Assert.NotNull(result);
        Assert.Same(expectedRequest, result);
    }

    /// <summary>
    /// Verifies that TryGetAsync returns null for unknown URI.
    /// Per OAuth 2.0 PAR, invalid or expired request_uri must be rejected.
    /// </summary>
    [Fact]
    public async Task TryGetAsync_WithUnknownUri_ShouldReturnNull()
    {
        // Arrange
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:unknown");

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync((AuthorizationRequest?)null);

        // Act
        var result = await _requestStorage.TryGetAsync(requestUri);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that TryGetAsync uses URI.OriginalString as storage key.
    /// Key format must match the format used in StoreAsync.
    /// </summary>
    [Fact]
    public async Task TryGetAsync_ShouldUseUriOriginalStringAsStorageKey()
    {
        // Arrange
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:get_key_test");
        var request = CreateMinimalRequest();

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request);

        // Act
        await _requestStorage.TryGetAsync(requestUri);

        // Assert
        _storage.Verify(
            s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that TryGetAsync passes shouldRemove=true to storage.
    /// Per OAuth 2.0 PAR, request should be removed after first use to prevent replay.
    /// </summary>
    [Fact]
    public async Task TryGetAsync_WithShouldRemoveTrue_ShouldPassToStorage()
    {
        // Arrange
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:remove_true");
        var request = CreateMinimalRequest();
        bool? capturedShouldRemove = null;

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                It.IsAny<string>(),
                It.IsAny<bool>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, bool, System.Threading.CancellationToken?>(
                (_, shouldRemove, _) => capturedShouldRemove = shouldRemove)
            .ReturnsAsync(request);

        // Act
        await _requestStorage.TryGetAsync(requestUri, true);

        // Assert
        Assert.True(capturedShouldRemove);
    }

    /// <summary>
    /// Verifies that TryGetAsync passes shouldRemove=false to storage.
    /// Non-destructive reads allow multiple validations before consumption.
    /// </summary>
    [Fact]
    public async Task TryGetAsync_WithShouldRemoveFalse_ShouldPassToStorage()
    {
        // Arrange
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:remove_false");
        var request = CreateMinimalRequest();
        bool? capturedShouldRemove = null;

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                It.IsAny<string>(),
                It.IsAny<bool>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, bool, System.Threading.CancellationToken?>(
                (_, shouldRemove, _) => capturedShouldRemove = shouldRemove)
            .ReturnsAsync(request);

        // Act
        await _requestStorage.TryGetAsync(requestUri);

        // Assert
        Assert.False(capturedShouldRemove);
    }

    /// <summary>
    /// Verifies that TryGetAsync calls storage.GetAsync exactly once.
    /// Single storage call ensures efficient retrieval without redundant operations.
    /// </summary>
    [Fact]
    public async Task TryGetAsync_ShouldCallStorageGetAsyncOnce()
    {
        // Arrange
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:get_once");
        var request = CreateMinimalRequest();

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request);

        // Act
        await _requestStorage.TryGetAsync(requestUri);

        // Assert
        _storage.Verify(
            s => s.GetAsync<AuthorizationRequest>(
                It.IsAny<string>(),
                It.IsAny<bool>(),
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that different URIs map to different storage keys.
    /// Each request_uri must have a unique storage location to prevent collisions.
    /// </summary>
    [Fact]
    public async Task TryGetAsync_DifferentUris_ShouldMapToDifferentKeys()
    {
        // Arrange
        var uri1 = new Uri("urn:ietf:params:oauth:request_uri:key1");
        var uri2 = new Uri("urn:ietf:params:oauth:request_uri:key2");
        var request1 = CreateMinimalRequest();
        var request2 = CreateCompleteRequest();

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{uri1.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request1);

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{uri2.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request2);

        // Act
        var result1 = await _requestStorage.TryGetAsync(uri1);
        var result2 = await _requestStorage.TryGetAsync(uri2);

        // Assert
        Assert.NotEqual(uri1.OriginalString, uri2.OriginalString);
        Assert.Same(request1, result1);
        Assert.Same(request2, result2);
    }

    /// <summary>
    /// Verifies Store then Get with shouldRemove=false returns request.
    /// Non-destructive retrieval allows multiple reads before consumption.
    /// </summary>
    [Fact]
    public async Task Integration_StoreThenGet_WithShouldRemoveFalse_ShouldReturnRequest()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:integration1");

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                request,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request);

        // Act
        var storeResult = await _requestStorage.StoreAsync(request, expiresIn);
        var getResult = await _requestStorage.TryGetAsync(storeResult.RequestUri);

        // Assert
        Assert.Same(request, getResult);
    }

    /// <summary>
    /// Verifies Store then Get with shouldRemove=true returns request.
    /// Per OAuth 2.0 PAR, request should be consumable with removal flag.
    /// </summary>
    [Fact]
    public async Task Integration_StoreThenGet_WithShouldRemoveTrue_ShouldReturnRequest()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:integration2");

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                request,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                true,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request);

        // Act
        var storeResult = await _requestStorage.StoreAsync(request, expiresIn);
        var getResult = await _requestStorage.TryGetAsync(storeResult.RequestUri, true);

        // Assert
        Assert.Same(request, getResult);
    }

    /// <summary>
    /// Verifies multiple sequential Gets with shouldRemove=false.
    /// Non-destructive reads must support repeated retrieval.
    /// </summary>
    [Fact]
    public async Task Integration_MultipleSequentialGets_WithShouldRemoveFalse_ShouldSucceed()
    {
        // Arrange
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:multiple_gets");
        var request = CreateMinimalRequest();

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request);

        // Act
        var result1 = await _requestStorage.TryGetAsync(requestUri);
        var result2 = await _requestStorage.TryGetAsync(requestUri);
        var result3 = await _requestStorage.TryGetAsync(requestUri);

        // Assert
        Assert.Same(request, result1);
        Assert.Same(request, result2);
        Assert.Same(request, result3);
        _storage.Verify(
            s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Exactly(3));
    }

    /// <summary>
    /// Verifies Get with shouldRemove=true simulates removal.
    /// Per OAuth 2.0 PAR, consumed requests should not be retrievable again.
    /// </summary>
    [Fact]
    public async Task Integration_GetWithShouldRemoveTrue_SimulatesRemoval()
    {
        // Arrange
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:simulate_removal");
        var request = CreateMinimalRequest();

        _storage
            .SetupSequence(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                true,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request)
            .ReturnsAsync((AuthorizationRequest?)null);

        // Act
        var firstGet = await _requestStorage.TryGetAsync(requestUri, true);
        var secondGet = await _requestStorage.TryGetAsync(requestUri, true);

        // Assert
        Assert.Same(request, firstGet);
        Assert.Null(secondGet);
    }

    /// <summary>
    /// Verifies multiple different requests stored independently.
    /// Storage must support concurrent tracking of many authorization requests.
    /// </summary>
    [Fact]
    public async Task Integration_MultipleDifferentRequests_StoredIndependently()
    {
        // Arrange
        var request1 = CreateMinimalRequest();
        var request2 = CreateCompleteRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var uri1 = new Uri("urn:ietf:params:oauth:request_uri:multi1");
        var uri2 = new Uri("urn:ietf:params:oauth:request_uri:multi2");

        _uriGenerator
            .SetupSequence(g => g.GenerateRequestUri())
            .Returns(uri1)
            .Returns(uri2);

        _storage
            .Setup(s => s.SetAsync(
                $"Abblix.Oidc.Server:PAR:{uri1.OriginalString}",
                request1,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.SetAsync(
                $"Abblix.Oidc.Server:PAR:{uri2.OriginalString}",
                request2,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{uri1.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request1);

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{uri2.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request2);

        // Act
        var store1 = await _requestStorage.StoreAsync(request1, expiresIn);
        var store2 = await _requestStorage.StoreAsync(request2, expiresIn);
        var get1 = await _requestStorage.TryGetAsync(store1.RequestUri);
        var get2 = await _requestStorage.TryGetAsync(store2.RequestUri);

        // Assert
        Assert.Same(request1, get1);
        Assert.Same(request2, get2);
        Assert.NotEqual(store1.RequestUri, store2.RequestUri);
    }

    /// <summary>
    /// Verifies different URIs retrieve correct requests.
    /// Storage must maintain correct request-to-URI mappings.
    /// </summary>
    [Fact]
    public async Task Integration_DifferentUris_RetrieveCorrectRequests()
    {
        // Arrange
        var uri1 = new Uri("urn:ietf:params:oauth:request_uri:correct1");
        var uri2 = new Uri("urn:ietf:params:oauth:request_uri:correct2");
        var request1 = CreateMinimalRequest();
        var request2 = CreateCompleteRequest();

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{uri1.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request1);

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{uri2.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request2);

        // Act
        var result1 = await _requestStorage.TryGetAsync(uri1);
        var result2 = await _requestStorage.TryGetAsync(uri2);

        // Assert
        Assert.Same(request1, result1);
        Assert.Same(request2, result2);
    }

    /// <summary>
    /// Verifies Store-Get-Store cycle with same URI.
    /// Subsequent stores should overwrite previous entries if using same URI.
    /// </summary>
    [Fact]
    public async Task Integration_StoreGetStoreCycle_WithSameUri_ShouldWork()
    {
        // Arrange
        var request1 = CreateMinimalRequest();
        var request2 = CreateCompleteRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:cycle");

        _uriGenerator
            .SetupSequence(g => g.GenerateRequestUri())
            .Returns(requestUri)
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .SetupSequence(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request1)
            .ReturnsAsync(request2);

        // Act
        await _requestStorage.StoreAsync(request1, expiresIn);
        var getResult1 = await _requestStorage.TryGetAsync(requestUri);
        await _requestStorage.StoreAsync(request2, expiresIn);
        var getResult2 = await _requestStorage.TryGetAsync(requestUri);

        // Assert
        Assert.Same(request1, getResult1);
        Assert.Same(request2, getResult2);
        _storage.Verify(
            s => s.SetAsync(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Exactly(2));
    }

    /// <summary>
    /// Verifies request with minimum required fields stores and retrieves correctly.
    /// Basic authorization flow must work with minimal request data.
    /// </summary>
    [Fact]
    public async Task EdgeCase_RequestWithMinimumRequiredFields_ShouldWork()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:minimal");

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                request,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request);

        // Act
        var storeResult = await _requestStorage.StoreAsync(request, expiresIn);
        var getResult = await _requestStorage.TryGetAsync(storeResult.RequestUri);

        // Assert
        Assert.Same(request, getResult);
        Assert.NotNull(getResult!.ClientId);
        Assert.NotNull(getResult.ResponseType);
        Assert.NotNull(getResult.RedirectUri);
        Assert.NotEmpty(getResult.Scope);
    }

    /// <summary>
    /// Verifies request with all optional fields stores and retrieves correctly.
    /// Complete authorization requests must preserve all field values.
    /// </summary>
    [Fact]
    public async Task EdgeCase_RequestWithAllOptionalFields_ShouldWork()
    {
        // Arrange
        var request = CreateCompleteRequest();
        var expiresIn = TimeSpan.FromMinutes(10);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:complete");

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                request,
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Returns(Task.CompletedTask);

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{requestUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request);

        // Act
        var storeResult = await _requestStorage.StoreAsync(request, expiresIn);
        var getResult = await _requestStorage.TryGetAsync(storeResult.RequestUri);

        // Assert
        Assert.Same(request, getResult);
        Assert.NotNull(getResult!.State);
        Assert.NotNull(getResult.Nonce);
        Assert.NotNull(getResult.MaxAge);
        Assert.NotNull(getResult.UiLocales);
        Assert.NotNull(getResult.CodeChallenge);
    }

    /// <summary>
    /// Verifies very short expiration (1 second) is handled correctly.
    /// Short-lived requests support quick authorization flows.
    /// </summary>
    [Fact]
    public async Task EdgeCase_VeryShortExpiration_ShouldBeHandled()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromSeconds(1);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:short_exp");
        StorageOptions? capturedOptions = null;

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, AuthorizationRequest, StorageOptions, System.Threading.CancellationToken?>(
                (_, _, options, _) => capturedOptions = options)
            .Returns(Task.CompletedTask);

        // Act
        await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.Equal(expiresIn, capturedOptions!.AbsoluteExpirationRelativeToNow);
    }

    /// <summary>
    /// Verifies very long expiration (1 year) is handled correctly.
    /// Long-lived requests support extended authorization scenarios.
    /// </summary>
    [Fact]
    public async Task EdgeCase_VeryLongExpiration_ShouldBeHandled()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var expiresIn = TimeSpan.FromDays(365);
        var requestUri = new Uri("urn:ietf:params:oauth:request_uri:long_exp");
        StorageOptions? capturedOptions = null;

        _uriGenerator
            .Setup(g => g.GenerateRequestUri())
            .Returns(requestUri);

        _storage
            .Setup(s => s.SetAsync(
                It.IsAny<string>(),
                It.IsAny<AuthorizationRequest>(),
                It.IsAny<StorageOptions>(),
                It.IsAny<System.Threading.CancellationToken?>()))
            .Callback<string, AuthorizationRequest, StorageOptions, System.Threading.CancellationToken?>(
                (_, _, options, _) => capturedOptions = options)
            .Returns(Task.CompletedTask);

        // Act
        await _requestStorage.StoreAsync(request, expiresIn);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.Equal(expiresIn, capturedOptions!.AbsoluteExpirationRelativeToNow);
    }

    /// <summary>
    /// Verifies different URI schemes (urn:, https://) are handled correctly.
    /// Per OAuth 2.0 PAR, request_uri typically uses urn: scheme but https: is also valid.
    /// </summary>
    [Fact]
    public async Task EdgeCase_DifferentUriSchemes_ShouldBeHandled()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var urnUri = new Uri("urn:ietf:params:oauth:request_uri:scheme_test");
        var httpsUri = new Uri("https://as.example.com/request_uri/abc123");

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{urnUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request);

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{httpsUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request);

        // Act
        var urnResult = await _requestStorage.TryGetAsync(urnUri);
        var httpsResult = await _requestStorage.TryGetAsync(httpsUri);

        // Assert
        Assert.Same(request, urnResult);
        Assert.Same(request, httpsResult);
        Assert.NotEqual(urnUri.OriginalString, httpsUri.OriginalString);
    }

    /// <summary>
    /// Verifies complex URI with query parameters and fragments is handled correctly.
    /// URI.OriginalString must preserve all components for correct key mapping.
    /// </summary>
    [Fact]
    public async Task EdgeCase_ComplexUriWithQueryAndFragment_ShouldBeHandled()
    {
        // Arrange
        var request = CreateMinimalRequest();
        var complexUri = new Uri("https://as.example.com/request?client_id=123&state=abc#fragment");

        _storage
            .Setup(s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{complexUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()))
            .ReturnsAsync(request);

        // Act
        var result = await _requestStorage.TryGetAsync(complexUri);

        // Assert
        Assert.Same(request, result);
        _storage.Verify(
            s => s.GetAsync<AuthorizationRequest>(
                $"Abblix.Oidc.Server:PAR:{complexUri.OriginalString}",
                false,
                It.IsAny<System.Threading.CancellationToken?>()),
            Times.Once);
    }
}
