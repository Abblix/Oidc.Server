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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="ClientIdValidator"/> verifying client ID validation
/// per OpenID Connect Dynamic Client Registration 1.0 specification.
/// </summary>
public class ClientIdValidatorTests
{
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly Mock<ILogger<ClientIdValidator>> _logger;
    private readonly ClientIdValidator _validator;

    public ClientIdValidatorTests()
    {
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        _logger = new Mock<ILogger<ClientIdValidator>>();
        _validator = new ClientIdValidator(_clientInfoProvider.Object, _logger.Object);
    }

    private ClientRegistrationValidationContext CreateContext(string? clientId = null)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [new Uri("https://example.com/callback")],
            ClientId = clientId
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Verifies validation succeeds when no client_id is specified.
    /// Per OIDC DCR spec, client_id is optional in registration request.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoClientId_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(clientId: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// Verifies validation succeeds when client_id is empty string.
    /// Empty string is treated as no client_id provided.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyClientId_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(clientId: string.Empty);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// Verifies validation succeeds when client_id is whitespace.
    /// Whitespace client ID is validated like any other string.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithWhitespaceClientId_ShouldCheckIfRegistered()
    {
        // Arrange
        var context = CreateContext(clientId: "   ");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("   "))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync("   "), Times.Once);
    }

    /// <summary>
    /// Verifies validation succeeds when client_id is not yet registered.
    /// Per OIDC DCR spec, clients can request specific client_id if available.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnregisteredClientId_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(clientId: "new-client");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("new-client"))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync("new-client"), Times.Once);
    }

    /// <summary>
    /// Verifies error when client_id is already registered.
    /// Per OIDC DCR spec, duplicate client_id must be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAlreadyRegisteredClientId_ShouldReturnInvalidClientMetadata()
    {
        // Arrange
        var context = CreateContext(clientId: "existing-client");

        var existingClient = new ClientInfo("existing-client");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("existing-client"))
            .ReturnsAsync(existingClient);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("already registered", result.ErrorDescription);
        Assert.Contains("existing-client", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validator checks client provider for existence.
    /// Ensures proper delegation to client info provider.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallClientInfoProvider()
    {
        // Arrange
        var context = CreateContext(clientId: "test-client");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("test-client"))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _clientInfoProvider.Verify(p => p.TryFindClientAsync("test-client"), Times.Once);
    }

    /// <summary>
    /// Verifies case-sensitive client_id matching.
    /// Client IDs are case-sensitive per OAuth 2.0 specification.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentCaseClientId_ShouldCheckExactCase()
    {
        // Arrange
        var context = CreateContext(clientId: "TestClient");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("TestClient"))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync("TestClient"), Times.Once);
    }

    /// <summary>
    /// Verifies special characters in client_id are handled.
    /// Client IDs may contain various characters per OAuth 2.0.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSpecialCharactersInClientId_ShouldValidate()
    {
        // Arrange
        var context = CreateContext(clientId: "client-123_456.test");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("client-123_456.test"))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies UUID format client_id is supported.
    /// UUIDs are common format for client identifiers.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUuidClientId_ShouldValidate()
    {
        // Arrange
        var uuid = "550e8400-e29b-41d4-a716-446655440000";
        var context = CreateContext(clientId: uuid);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(uuid))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies long client_id is handled.
    /// Tests boundary conditions for client ID length.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithLongClientId_ShouldValidate()
    {
        // Arrange
        var longClientId = new string('a', 256);
        var context = CreateContext(clientId: longClientId);

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(longClientId))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies single character client_id is valid.
    /// Tests minimum length edge case.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSingleCharacterClientId_ShouldValidate()
    {
        // Arrange
        var context = CreateContext(clientId: "a");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("a"))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }
}
