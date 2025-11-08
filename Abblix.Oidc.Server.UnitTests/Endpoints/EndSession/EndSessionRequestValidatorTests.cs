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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession;

/// <summary>
/// Unit tests for <see cref="EndSessionRequestValidator"/> verifying end session request
/// validation per OIDC Session Management specification.
/// </summary>
public class EndSessionRequestValidatorTests
{
    private readonly Mock<IEndSessionContextValidator> _contextValidator;
    private readonly EndSessionRequestValidator _validator;

    public EndSessionRequestValidatorTests()
    {
        _contextValidator = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        _validator = new EndSessionRequestValidator(_contextValidator.Object);
    }

    private static EndSessionRequest CreateEndSessionRequest(
        string? idTokenHint = "id_token_value",
        string? postLogoutRedirectUri = "https://client.example.com/logout",
        string? state = "state_123",
        string? clientId = null)
    {
        return new EndSessionRequest
        {
            IdTokenHint = idTokenHint,
            PostLogoutRedirectUri = postLogoutRedirectUri != null ? new Uri(postLogoutRedirectUri) : null,
            State = state,
            ClientId = clientId,
        };
    }

    /// <summary>
    /// Verifies successful validation with valid end session request.
    /// Per OIDC Session Management, validator should delegate to context validator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidRequest_ShouldReturnValidEndSessionRequest()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest(clientId: "client_123");
        var clientInfo = new ClientInfo("client_123");

        _contextValidator
            .Setup(v => v.ValidateAsync(It.Is<EndSessionValidationContext>(c => c.Request == endSessionRequest)))
            .Callback(new Action<EndSessionValidationContext>(ctx => ctx.ClientInfo = clientInfo))
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(endSessionRequest, validRequest.Model);
        Assert.Same(clientInfo, validRequest.ClientInfo);
        _contextValidator.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
    }

    /// <summary>
    /// Verifies validation error propagation.
    /// Context validator errors should be returned as-is.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidationError_ShouldReturnError()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest();
        var error = new OidcError(
            ErrorCodes.InvalidRequest,
            "Invalid id_token_hint");

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .ReturnsAsync(error);

        // Act
        var result = await _validator.ValidateAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var actualError));
        Assert.Same(error, actualError);
        _contextValidator.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
    }

    /// <summary>
    /// Verifies context creation with request data.
    /// Validator should create EndSessionValidationContext with correct request.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCreateContextWithRequest()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest();
        EndSessionValidationContext? capturedContext = null;

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .Callback(new Action<EndSessionValidationContext>(ctx => capturedContext = ctx))
            .ReturnsAsync((OidcError?)null);

        // Act
        await _validator.ValidateAsync(endSessionRequest);

        // Assert
        Assert.NotNull(capturedContext);
        Assert.Same(endSessionRequest, capturedContext.Request);
        _contextValidator.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
    }

    /// <summary>
    /// Verifies context validator is called exactly once.
    /// Tests single invocation of validation logic.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallContextValidatorOnce()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest();

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .ReturnsAsync((OidcError?)null);

        // Act
        await _validator.ValidateAsync(endSessionRequest);

        // Assert
        _contextValidator.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
    }

    /// <summary>
    /// Verifies ClientInfo is extracted from context.
    /// ValidEndSessionRequest should contain ClientInfo set by context validator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldExtractClientInfoFromContext()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest();
        var expectedClientInfo = new ClientInfo("client_456");

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .Callback(new Action<EndSessionValidationContext>(ctx => ctx.ClientInfo = expectedClientInfo))
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(expectedClientInfo, validRequest.ClientInfo);
    }

    /// <summary>
    /// Verifies error details are preserved.
    /// Error code and description should match context validator error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnError_ShouldPreserveErrorDetails()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest();
        var error = new OidcError(
            ErrorCodes.InvalidClient,
            "Client not found");

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .ReturnsAsync(error);

        // Act
        var result = await _validator.ValidateAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var actualError));
        Assert.Equal(ErrorCodes.InvalidClient, actualError.Error);
        Assert.Equal("Client not found", actualError.ErrorDescription);
    }

    /// <summary>
    /// Verifies request with all parameters is handled correctly.
    /// Tests validation with id_token_hint, redirect URI, state, and clientId.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAllParameters_ShouldSucceed()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest(
            idTokenHint: "token_123",
            postLogoutRedirectUri: "https://app.example.com/signout",
            state: "xyz789",
            clientId: "client_999");
        var clientInfo = new ClientInfo("client_999");

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .Callback(new Action<EndSessionValidationContext>(ctx => ctx.ClientInfo = clientInfo))
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(endSessionRequest, validRequest.Model);
        Assert.Equal("token_123", validRequest.Model.IdTokenHint);
        Assert.Equal("https://app.example.com/signout", validRequest.Model.PostLogoutRedirectUri?.ToString());
        Assert.Equal("xyz789", validRequest.Model.State);
        Assert.Equal("client_999", validRequest.Model.ClientId);
    }

    /// <summary>
    /// Verifies request with minimal parameters is handled correctly.
    /// Tests validation with only required parameters.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMinimalParameters_ShouldSucceed()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest(
            idTokenHint: null,
            postLogoutRedirectUri: null,
            state: null,
            clientId: null);

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(endSessionRequest, validRequest.Model);
    }

    /// <summary>
    /// Verifies ValidEndSessionRequest structure.
    /// Tests that result contains both request and client info.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldReturnCompleteValidRequest()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest(clientId: "client_123");
        var clientInfo = new ClientInfo("client_123");

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .Callback(new Action<EndSessionValidationContext>(ctx => ctx.ClientInfo = clientInfo))
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(validRequest.Model);
        Assert.NotNull(validRequest.ClientInfo);
        Assert.Same(endSessionRequest, validRequest.Model);
        Assert.Same(clientInfo, validRequest.ClientInfo);
    }

    /// <summary>
    /// Verifies validator doesn't modify request.
    /// Request should remain unchanged after validation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldNotModifyRequest()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest(
            idTokenHint: "original_token",
            postLogoutRedirectUri: "https://original.example.com/logout",
            state: "original_state",
            clientId: "original_client");

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .ReturnsAsync((OidcError?)null);

        // Act
        await _validator.ValidateAsync(endSessionRequest);

        // Assert
        Assert.Equal("original_token", endSessionRequest.IdTokenHint);
        Assert.Equal("https://original.example.com/logout", endSessionRequest.PostLogoutRedirectUri?.ToString());
        Assert.Equal("original_state", endSessionRequest.State);
        Assert.Equal("original_client", endSessionRequest.ClientId);
    }
}
