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
// must occur within the official GitHub repository and are managed solely by Abblix LLP.
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

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession.Validation;

/// <summary>
/// Unit tests for <see cref="ClientValidator"/> verifying client validation
/// for end-session requests per OIDC Session Management specification.
/// </summary>
public class ClientValidatorTests
{
    private readonly Mock<ILogger<ClientValidator>> _logger;
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly ClientValidator _validator;

    public ClientValidatorTests()
    {
        LicenseTestHelper.StartTest();

        _logger = new Mock<ILogger<ClientValidator>>();
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        _validator = new ClientValidator(_logger.Object, _clientInfoProvider.Object);
    }

    private static EndSessionValidationContext CreateContext(string? clientId = "client_123")
    {
        var request = new EndSessionRequest
        {
            ClientId = clientId,
        };
        var context = new EndSessionValidationContext(request);
        if (clientId != null)
        {
            context.ClientId = clientId;
        }
        return context;
    }

    /// <summary>
    /// Verifies successful validation when no client ID provided.
    /// Per OIDC Session Management, client ID is optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutClientId_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(clientId: null);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies successful validation with valid client ID.
    /// Client must be found in the client info provider.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidClientId_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext("client_123");
        var clientInfo = new ClientInfo("client_123");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("client_123"))
            .ReturnsAsync(clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Same(clientInfo, context.ClientInfo);
    }

    /// <summary>
    /// Verifies error when client not found.
    /// Per OIDC, unknown clients should be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnknownClient_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext("unknown_client");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("unknown_client"))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.UnauthorizedClient, error.Error);
        Assert.Contains("not authorized", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies client info is set in context when client found.
    /// Downstream validators need access to client info.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetClientInfoInContext()
    {
        // Arrange
        var context = CreateContext("client_456");
        var clientInfo = new ClientInfo("client_456");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("client_456"))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Same(clientInfo, context.ClientInfo);
    }

    /// <summary>
    /// Verifies empty client ID is treated as no client ID.
    /// Empty string should be considered as not having a value.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyClientId_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext("");

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies client info provider is called with correct client ID.
    /// Tests data flow from context to provider.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallClientInfoProviderWithClientId()
    {
        // Arrange
        var context = CreateContext("specific_client_789");
        var clientInfo = new ClientInfo("specific_client_789");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("specific_client_789"))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _clientInfoProvider.Verify(p => p.TryFindClientAsync("specific_client_789"), Times.Once);
    }

    /// <summary>
    /// Verifies client info provider is not called when no client ID.
    /// Optimization: skip lookup when not needed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutClientId_ShouldNotCallClientInfoProvider()
    {
        // Arrange
        var context = CreateContext(clientId: null);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _clientInfoProvider.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies client info is not set when client not found.
    /// Context should remain unchanged on error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenClientNotFound_ShouldNotSetClientInfo()
    {
        // Arrange
        var context = CreateContext("unknown_client");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("unknown_client"))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(context.ClientInfo);
    }

    /// <summary>
    /// Verifies case-sensitive client ID matching.
    /// Per OAuth 2.0, client IDs are case-sensitive.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldMatchClientIdCaseSensitive()
    {
        // Arrange
        var context = CreateContext("Client_123");
        var clientInfo = new ClientInfo("Client_123");

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("Client_123"))
            .ReturnsAsync(clientInfo);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        _clientInfoProvider.Verify(p => p.TryFindClientAsync("Client_123"), Times.Once);
    }

}
