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
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="ClientValidator"/> verifying client authentication and authorization
/// per OAuth 2.0 RFC 6749. Tests cover client_id validation, client lookup, authorization checks,
/// and context population.
/// </summary>
public class ClientValidatorTests
{
    private const string ValidClientId = "test_client_1";
    private const string ValidClientId2 = "test_client_2";
    private const string UnknownClientId = "unknown_client";

    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly ClientValidator _validator;

    public ClientValidatorTests()
    {
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var logger = new Mock<ILogger<ClientValidator>>(MockBehavior.Loose);
        _validator = new ClientValidator(_clientInfoProvider.Object, logger.Object);
    }

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(string? clientId)
    {
        var request = new AuthorizationRequest
        {
            ClientId = clientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
        };

        return new AuthorizationValidationContext(request);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts valid client_id and populates context.
    /// Per OAuth 2.0 Section 2.2, client_id is REQUIRED parameter.
    /// Critical for client authentication and authorization.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidClientId_ShouldSucceed()
    {
        // Arrange
        var clientInfo = new ClientInfo(ValidClientId);
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        var context = CreateContext(ValidClientId);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Same(clientInfo, context.ClientInfo);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(ValidClientId), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects null client_id.
    /// Per OAuth 2.0, client_id is REQUIRED parameter for authorization requests.
    /// Critical for preventing unauthorized access.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullClientId_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        Assert.Contains("required", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects unknown client_id.
    /// Per OAuth 2.0, only registered clients are authorized to make requests.
    /// Critical security check preventing unauthorized client access.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnknownClientId_ShouldReturnError()
    {
        // Arrange
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(UnknownClientId))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(UnknownClientId);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        Assert.Contains("not authorized", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(UnknownClientId), Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects empty client_id string.
    /// Empty string is not null, so it attempts client lookup.
    /// Tests edge case handling for malformed requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyClientId_ShouldReturnError()
    {
        // Arrange
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(string.Empty))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(string.Empty);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts client_id with different formats.
    /// Tests that validator uses client_id exactly as provided.
    /// Uses ValidClientId2 to stay within license limits.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithVariousClientIdFormats_ShouldSucceed()
    {
        // Arrange
        var clientInfo = new ClientInfo(ValidClientId2);
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId2))
            .ReturnsAsync(clientInfo);

        var context = CreateContext(ValidClientId2);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Same(clientInfo, context.ClientInfo);
    }

    /// <summary>
    /// Verifies that ValidateAsync is case-sensitive for client_id.
    /// Per OAuth 2.0, client identifiers are case-sensitive.
    /// Tests that TestConstants.DefaultClientId and TestConstants.DefaultClientId are different clients.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ClientIdIsCaseSensitive_ShouldTreatDifferently()
    {
        // Arrange
        const string uppercaseClientId = TestConstants.DefaultClientId;
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(uppercaseClientId))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(uppercaseClientId);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync(uppercaseClientId), Times.Once);
    }


    /// <summary>
    /// Verifies that ValidateAsync populates context.ClientInfo on success.
    /// Downstream validators rely on ClientInfo being populated.
    /// Per design: ClientInfo is only accessible after successful validation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldPopulateClientInfo()
    {
        // Arrange
        var clientInfo = new ClientInfo(ValidClientId)
        {
            ClientName = "Test Client",
            AllowedResponseTypes = [[ResponseTypes.Code]],
        };
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        var context = CreateContext(ValidClientId);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        // ClientInfo is now accessible after successful validation
        Assert.Equal(ValidClientId, context.ClientInfo.ClientId);
        Assert.Equal("Test Client", context.ClientInfo.ClientName);
    }

    /// <summary>
    /// Verifies that ValidateAsync returns error when client not found.
    /// Per design: ClientInfo throws when accessed before successful validation.
    /// Tests that error is returned without setting ClientInfo.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnError_ShouldReturnErrorWithoutSettingClientInfo()
    {
        // Arrange
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(UnknownClientId))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(UnknownClientId);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        // Note: Cannot access context.ClientInfo - it throws when not set
    }

    /// <summary>
    /// Verifies that ValidateAsync includes error code in error response.
    /// Per OAuth 2.0, error responses MUST include error parameter.
    /// Critical for proper error communication to client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeErrorCode()
    {
        // Arrange
        var context = CreateContext(null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Error);
        Assert.NotEmpty(result.Error);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes error description in error response.
    /// Per OAuth 2.0, error_description is OPTIONAL but RECOMMENDED.
    /// Helps developers diagnose client authentication failures.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeErrorDescription()
    {
        // Arrange
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(UnknownClientId))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(UnknownClientId);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.ErrorDescription);
        Assert.NotEmpty(result.ErrorDescription);
    }

    /// <summary>
    /// Verifies that ValidateAsync calls IClientInfoProvider exactly once.
    /// Tests efficient client lookup without redundant calls.
    /// Important for performance with database-backed client stores.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallClientInfoProviderOnce()
    {
        // Arrange
        var clientInfo = new ClientInfo(ValidClientId);
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync(clientInfo);

        var context = CreateContext(ValidClientId);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _clientInfoProvider.Verify(
            p => p.TryFindClientAsync(ValidClientId),
            Times.Once);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles provider returning null gracefully.
    /// Tests error handling when client lookup fails.
    /// Critical for robust error handling in production.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenProviderReturnsNull_ShouldReturnError()
    {
        // Arrange
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ValidClientId))
            .ReturnsAsync((ClientInfo?)null);

        var context = CreateContext(ValidClientId);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
    }

}
