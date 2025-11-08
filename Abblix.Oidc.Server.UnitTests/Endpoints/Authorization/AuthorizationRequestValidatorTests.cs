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
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

/// <summary>
/// Unit tests for <see cref="AuthorizationRequestValidator"/> verifying composite validator
/// behavior implementing Chain of Responsibility pattern for authorization request validation.
/// </summary>
public class AuthorizationRequestValidatorTests
{
    private readonly Mock<IAuthorizationContextValidator> _contextValidator;
    private readonly AuthorizationRequestValidator _validator;

    public AuthorizationRequestValidatorTests()
    {
        _contextValidator = new Mock<IAuthorizationContextValidator>(MockBehavior.Strict);
        _validator = new AuthorizationRequestValidator(_contextValidator.Object);
    }

    private static AuthorizationRequest CreateRequest() => new()
    {
        ClientId = "client_123",
        ResponseType = [ResponseTypes.Code],
        RedirectUri = new Uri("https://client.example.com/callback"),
        Scope = [Scopes.OpenId],
    };

    /// <summary>
    /// Verifies successful validation returns ValidAuthorizationRequest.
    /// Tests happy path where context validator succeeds.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenContextValidatorSucceeds_ShouldReturnValidRequest()
    {
        // Arrange
        var request = CreateRequest();
        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthorizationValidationContext>()))
            .Callback<AuthorizationValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.ResponseMode = ResponseModes.Query;
            })
            .ReturnsAsync((AuthorizationRequestValidationError?)null);

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(validRequest);
        Assert.Equal(request.ClientId, validRequest.Model.ClientId);
    }

    /// <summary>
    /// Verifies validation error returns error response.
    /// Tests error propagation from context validator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenContextValidatorFails_ShouldReturnError()
    {
        // Arrange
        var request = CreateRequest();
        var error = new AuthorizationRequestValidationError(
            ErrorCodes.InvalidScope,
            "Invalid scope",
            request.RedirectUri,
            ResponseModes.Query);

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthorizationValidationContext>()))
            .ReturnsAsync(error);

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
    }

    /// <summary>
    /// Verifies ValidateAsync creates AuthorizationValidationContext correctly.
    /// Tests context creation with request data.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCreateContextWithRequest()
    {
        // Arrange
        var request = CreateRequest();
        AuthorizationValidationContext? capturedContext = null;

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthorizationValidationContext>()))
            .Callback<AuthorizationValidationContext>(ctx =>
            {
                capturedContext = ctx;
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.ResponseMode = ResponseModes.Query;
            })
            .ReturnsAsync((AuthorizationRequestValidationError?)null);

        // Act
        await _validator.ValidateAsync(request);

        // Assert
        Assert.NotNull(capturedContext);
        Assert.Same(request, capturedContext.Request);
    }

    /// <summary>
    /// Verifies ValidateAsync calls context validator exactly once.
    /// Tests efficient validation without redundant calls.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallContextValidatorOnce()
    {
        // Arrange
        var request = CreateRequest();
        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthorizationValidationContext>()))
            .Callback<AuthorizationValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.ResponseMode = ResponseModes.Query;
            })
            .ReturnsAsync((AuthorizationRequestValidationError?)null);

        // Act
        await _validator.ValidateAsync(request);

        // Assert
        _contextValidator.Verify(
            v => v.ValidateAsync(It.IsAny<AuthorizationValidationContext>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies ValidateAsync wraps validated context in ValidAuthorizationRequest.
    /// Tests correct transformation from context to valid request.
    /// Critical for downstream processing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldWrapContextInValidRequest()
    {
        // Arrange
        var request = CreateRequest();
        AuthorizationValidationContext? capturedContext = null;

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthorizationValidationContext>()))
            .Callback<AuthorizationValidationContext>(ctx =>
            {
                capturedContext = ctx;
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.ResponseMode = ResponseModes.Query;
            })
            .ReturnsAsync((AuthorizationRequestValidationError?)null);

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(capturedContext);
        Assert.Same(capturedContext.Request, validRequest.Model);
        Assert.Same(capturedContext.ClientInfo, validRequest.ClientInfo);
        Assert.Equal(capturedContext.ResponseMode, validRequest.ResponseMode);
    }

    /// <summary>
    /// Verifies ValidateAsync handles null error as success.
    /// Per design: null error indicates validation success.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenValidatorReturnsNull_ShouldSucceed()
    {
        // Arrange
        var request = CreateRequest();
        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthorizationValidationContext>()))
            .Callback<AuthorizationValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.ResponseMode = ResponseModes.Query;
            })
            .ReturnsAsync((AuthorizationRequestValidationError?)null);

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(validRequest);
    }

    /// <summary>
    /// Verifies ValidateAsync preserves error details.
    /// Tests that error code and description are preserved.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnError_ShouldPreserveErrorDetails()
    {
        // Arrange
        var request = CreateRequest();
        var error = new AuthorizationRequestValidationError(
            ErrorCodes.UnauthorizedClient,
            "Client not authorized for this operation",
            request.RedirectUri,
            ResponseModes.Query);

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthorizationValidationContext>()))
            .ReturnsAsync(error);

        // Act
        var result = await _validator.ValidateAsync(request);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(ErrorCodes.UnauthorizedClient, failure.Error);
        Assert.Equal("Client not authorized for this operation", failure.ErrorDescription);
    }

    /// <summary>
    /// Verifies ValidateAsync creates fresh context for each request.
    /// Tests that validator doesn't reuse contexts.
    /// Important for concurrent request handling.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCreateNewContextForEachRequest()
    {
        // Arrange
        var request1 = CreateRequest();
        var request2 = CreateRequest();
        var capturedContexts = new System.Collections.Generic.List<AuthorizationValidationContext>();

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthorizationValidationContext>()))
            .Callback<AuthorizationValidationContext>(ctx =>
            {
                capturedContexts.Add(ctx);
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.ResponseMode = ResponseModes.Query;
            })
            .ReturnsAsync((AuthorizationRequestValidationError?)null);

        // Act
        await _validator.ValidateAsync(request1);
        await _validator.ValidateAsync(request2);

        // Assert
        Assert.Equal(2, capturedContexts.Count);
        Assert.NotSame(capturedContexts[0], capturedContexts[1]);
    }

    /// <summary>
    /// Verifies ValidateAsync with different request parameters.
    /// Tests validator handles various request configurations.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentRequests_ShouldValidateEach()
    {
        // Arrange
        var request1 = new AuthorizationRequest
        {
            ClientId = "client_1",
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client1.example.com/callback"),
            Scope = [Scopes.OpenId],
        };

        var request2 = new AuthorizationRequest
        {
            ClientId = "client_2",
            ResponseType = [ResponseTypes.Code, ResponseTypes.IdToken],
            RedirectUri = new Uri("https://client2.example.com/callback"),
            Scope = [Scopes.OpenId, Scopes.Profile],
        };

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<AuthorizationValidationContext>()))
            .Callback<AuthorizationValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo(ctx.Request.ClientId!);
                ctx.ResponseMode = ResponseModes.Query;
            })
            .ReturnsAsync((AuthorizationRequestValidationError?)null);

        // Act
        var result1 = await _validator.ValidateAsync(request1);
        var result2 = await _validator.ValidateAsync(request2);

        // Assert
        Assert.True(result1.TryGetSuccess(out var validRequest1));
        Assert.True(result2.TryGetSuccess(out var validRequest2));
        Assert.Equal("client_1", validRequest1.Model.ClientId);
        Assert.Equal("client_2", validRequest2.Model.ClientId);
        _contextValidator.Verify(
            v => v.ValidateAsync(It.IsAny<AuthorizationValidationContext>()),
            Times.Exactly(2));
    }

    /// <summary>
    /// Verifies ValidateAsync passes same context to validator that was created.
    /// Tests that context isn't modified between creation and validation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPassCreatedContextToValidator()
    {
        // Arrange
        var request = CreateRequest();
        AuthorizationValidationContext? capturedContext = null;

        _contextValidator
            .Setup(v => v.ValidateAsync(It.Is<AuthorizationValidationContext>(ctx => ctx.Request == request)))
            .Callback<AuthorizationValidationContext>(ctx =>
            {
                capturedContext = ctx;
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.ResponseMode = ResponseModes.Query;
            })
            .ReturnsAsync((AuthorizationRequestValidationError?)null);

        // Act
        await _validator.ValidateAsync(request);

        // Assert
        Assert.NotNull(capturedContext);
        Assert.Same(request, capturedContext.Request);
        _contextValidator.Verify(
            v => v.ValidateAsync(It.Is<AuthorizationValidationContext>(ctx => ctx.Request == request)),
            Times.Once);
    }
}
