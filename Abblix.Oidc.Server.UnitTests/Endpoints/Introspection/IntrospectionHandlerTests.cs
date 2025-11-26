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

using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Introspection;

/// <summary>
/// Unit tests for <see cref="IntrospectionHandler"/> verifying request orchestration
/// (validate → process) per RFC 7662 Token Introspection specification.
/// </summary>
public class IntrospectionHandlerTests
{
    private readonly Mock<IIntrospectionRequestValidator> _validator;
    private readonly Mock<IIntrospectionRequestProcessor> _processor;
    private readonly IntrospectionHandler _handler;

    public IntrospectionHandlerTests()
    {
        _validator = new Mock<IIntrospectionRequestValidator>(MockBehavior.Strict);
        _processor = new Mock<IIntrospectionRequestProcessor>(MockBehavior.Strict);
        _handler = new IntrospectionHandler(_validator.Object, _processor.Object);
    }

    private static IntrospectionRequest CreateIntrospectionRequest() => new()
    {
        Token = "access_token_value",
        TokenTypeHint = "access_token",
    };

    private static ClientRequest CreateClientRequest() => new()
    {
        ClientId = TestConstants.DefaultClientId,
    };

    private static ValidIntrospectionRequest CreateValidIntrospectionRequest(IntrospectionRequest request)
    {
        var token = new Jwt.JsonWebToken();
        return new ValidIntrospectionRequest(request, token);
    }

    private static IntrospectionSuccess CreateIntrospectionSuccess(bool active)
    {
        var claims = active ? new JsonObject { ["sub"] = "user_123" } : null;
        return new IntrospectionSuccess(active, claims);
    }

    /// <summary>
    /// Verifies successful introspection flow: validate → process.
    /// Tests happy path where validation and processing both succeed.
    /// </summary>
    [Fact]
    public async Task HandleAsync_SuccessfulFlow_ShouldReturnIntrospectionSuccess()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidIntrospectionRequest(introspectionRequest);
        var introspectionSuccess = CreateIntrospectionSuccess(true);

        _validator
            .Setup(v => v.ValidateAsync(introspectionRequest, clientRequest))
            .ReturnsAsync(Result<ValidIntrospectionRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<IntrospectionSuccess, OidcError>.Success(introspectionSuccess));

        // Act
        var result = await _handler.HandleAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.Same(introspectionSuccess, success);
        _validator.Verify(v => v.ValidateAsync(introspectionRequest, clientRequest), Times.Once);
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies validation error handling.
    /// Per RFC 7662, validation errors should return error response without processing.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ValidationError_ShouldReturnError()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(
            ErrorCodes.InvalidClient,
            "Client authentication failed");

        _validator
            .Setup(v => v.ValidateAsync(introspectionRequest, clientRequest))
            .ReturnsAsync(Result<ValidIntrospectionRequest, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
        _validator.Verify(v => v.ValidateAsync(introspectionRequest, clientRequest), Times.Once);
        _processor.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies processing error handling.
    /// Tests error propagation from processor after successful validation.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ProcessingError_ShouldReturnError()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidIntrospectionRequest(introspectionRequest);
        var error = new OidcError(
            ErrorCodes.ServerError,
            "Failed to introspect token");

        _validator
            .Setup(v => v.ValidateAsync(introspectionRequest, clientRequest))
            .ReturnsAsync(Result<ValidIntrospectionRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<IntrospectionSuccess, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
        _validator.Verify(v => v.ValidateAsync(introspectionRequest, clientRequest), Times.Once);
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies that validated request is passed to processor.
    /// Tests data flow from validator to processor.
    /// Critical for correct introspection response.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldPassValidatedRequestToProcessor()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidIntrospectionRequest(introspectionRequest);
        var introspectionSuccess = CreateIntrospectionSuccess(true);

        _validator
            .Setup(v => v.ValidateAsync(introspectionRequest, clientRequest))
            .ReturnsAsync(Result<ValidIntrospectionRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(It.Is<ValidIntrospectionRequest>(r => r == validRequest)))
            .ReturnsAsync(Result<IntrospectionSuccess, OidcError>.Success(introspectionSuccess));

        // Act
        await _handler.HandleAsync(introspectionRequest, clientRequest);

        // Assert
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies sequential execution: validate before process.
    /// Tests that components are called in correct order.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldCallValidatorBeforeProcessor()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidIntrospectionRequest(introspectionRequest);
        var introspectionSuccess = CreateIntrospectionSuccess(true);

        var callOrder = new System.Collections.Generic.List<string>();

        _validator
            .Setup(v => v.ValidateAsync(introspectionRequest, clientRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("validate");
                return Result<ValidIntrospectionRequest, OidcError>.Success(validRequest);
            });

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("process");
                return Result<IntrospectionSuccess, OidcError>.Success(introspectionSuccess);
            });

        // Act
        await _handler.HandleAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.Equal(2, callOrder.Count);
        Assert.Equal("validate", callOrder[0]);
        Assert.Equal("process", callOrder[1]);
    }

    /// <summary>
    /// Verifies error response includes error code.
    /// Per OAuth 2.0, error responses MUST include error parameter.
    /// </summary>
    [Fact]
    public async Task HandleAsync_OnError_ShouldIncludeErrorCode()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(
            ErrorCodes.InvalidGrant,
            "Token is invalid");

        _validator
            .Setup(v => v.ValidateAsync(introspectionRequest, clientRequest))
            .ReturnsAsync(Result<ValidIntrospectionRequest, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.NotNull(failure.Error);
        Assert.NotEmpty(failure.Error);
        Assert.Equal(ErrorCodes.InvalidGrant, failure.Error);
    }

    /// <summary>
    /// Verifies that validator is called with correct parameters.
    /// Tests that both introspectionRequest and clientRequest are passed to validator.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldCallValidatorWithBothRequests()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(ErrorCodes.InvalidRequest, "Invalid request");

        _validator
            .Setup(v => v.ValidateAsync(introspectionRequest, clientRequest))
            .ReturnsAsync(Result<ValidIntrospectionRequest, OidcError>.Failure(error));

        // Act
        await _handler.HandleAsync(introspectionRequest, clientRequest);

        // Assert
        _validator.Verify(
            v => v.ValidateAsync(
                It.Is<IntrospectionRequest>(r => r == introspectionRequest),
                It.Is<ClientRequest>(r => r == clientRequest)),
            Times.Once);
    }

    /// <summary>
    /// Verifies that processor is not called when validation fails.
    /// Per design: only validated requests should be processed.
    /// Important for security and correctness.
    /// </summary>
    [Fact]
    public async Task HandleAsync_WhenValidationFails_ShouldNotCallProcessor()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(ErrorCodes.InvalidClient, "Client not authorized");

        _validator
            .Setup(v => v.ValidateAsync(introspectionRequest, clientRequest))
            .ReturnsAsync(Result<ValidIntrospectionRequest, OidcError>.Failure(error));

        // Act
        await _handler.HandleAsync(introspectionRequest, clientRequest);

        // Assert
        _processor.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies introspection returns active status.
    /// Per RFC 7662, response MUST include active boolean indicator.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldReturnActiveStatus()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidIntrospectionRequest(introspectionRequest);
        var introspectionSuccess = CreateIntrospectionSuccess(true);

        _validator
            .Setup(v => v.ValidateAsync(introspectionRequest, clientRequest))
            .ReturnsAsync(Result<ValidIntrospectionRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<IntrospectionSuccess, OidcError>.Success(introspectionSuccess));

        // Act
        var result = await _handler.HandleAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.True(success.Active);
    }

    /// <summary>
    /// Verifies introspection can return inactive tokens.
    /// Per RFC 7662 Section 2.2, inactive tokens return active: false.
    /// </summary>
    [Fact]
    public async Task HandleAsync_WithInactiveToken_ShouldReturnInactiveStatus()
    {
        // Arrange
        var introspectionRequest = CreateIntrospectionRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidIntrospectionRequest(introspectionRequest);
        var introspectionSuccess = CreateIntrospectionSuccess(false);

        _validator
            .Setup(v => v.ValidateAsync(introspectionRequest, clientRequest))
            .ReturnsAsync(Result<ValidIntrospectionRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<IntrospectionSuccess, OidcError>.Success(introspectionSuccess));

        // Act
        var result = await _handler.HandleAsync(introspectionRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.False(success.Active);
        Assert.Null(success.Claims);
    }
}
