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
using Abblix.Oidc.Server.Endpoints.Revocation;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Revocation;

/// <summary>
/// Unit tests for <see cref="RevocationHandler"/> verifying request orchestration
/// (validate → process) per RFC 7009 Token Revocation specification.
/// </summary>
public class RevocationHandlerTests
{
    private readonly Mock<IRevocationRequestValidator> _validator;
    private readonly Mock<IRevocationRequestProcessor> _processor;
    private readonly RevocationHandler _handler;

    public RevocationHandlerTests()
    {
        _validator = new Mock<IRevocationRequestValidator>(MockBehavior.Strict);
        _processor = new Mock<IRevocationRequestProcessor>(MockBehavior.Strict);
        _handler = new RevocationHandler(_validator.Object, _processor.Object);
    }

    private static RevocationRequest CreateRevocationRequest() => new()
    {
        Token = "token_to_revoke",
        TokenTypeHint = "access_token",
    };

    private static ClientRequest CreateClientRequest() => new()
    {
        ClientId = "client_123",
    };

    private static ValidRevocationRequest CreateValidRevocationRequest(RevocationRequest request)
    {
        var token = new Jwt.JsonWebToken();
        return new ValidRevocationRequest(request, token);
    }

    private static TokenRevoked CreateTokenRevoked() => new(
        "token_id_123",
        "access_token",
        DateTimeOffset.UtcNow);

    /// <summary>
    /// Verifies successful revocation flow: validate → process.
    /// Tests happy path where validation and processing both succeed.
    /// </summary>
    [Fact]
    public async Task HandleAsync_SuccessfulFlow_ShouldReturnTokenRevoked()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidRevocationRequest(revocationRequest);
        var tokenRevoked = CreateTokenRevoked();

        _validator
            .Setup(v => v.ValidateAsync(revocationRequest, clientRequest))
            .ReturnsAsync(Result<ValidRevocationRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<TokenRevoked, OidcError>.Success(tokenRevoked));

        // Act
        var result = await _handler.HandleAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var revoked));
        Assert.Same(tokenRevoked, revoked);
        _validator.Verify(v => v.ValidateAsync(revocationRequest, clientRequest), Times.Once);
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies validation error handling.
    /// Per RFC 7009, validation errors should return error response without processing.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ValidationError_ShouldReturnError()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(
            ErrorCodes.InvalidClient,
            "Client authentication failed");

        _validator
            .Setup(v => v.ValidateAsync(revocationRequest, clientRequest))
            .ReturnsAsync(Result<ValidRevocationRequest, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
        _validator.Verify(v => v.ValidateAsync(revocationRequest, clientRequest), Times.Once);
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
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidRevocationRequest(revocationRequest);
        var error = new OidcError(
            ErrorCodes.ServerError,
            "Failed to revoke token");

        _validator
            .Setup(v => v.ValidateAsync(revocationRequest, clientRequest))
            .ReturnsAsync(Result<ValidRevocationRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<TokenRevoked, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
        _validator.Verify(v => v.ValidateAsync(revocationRequest, clientRequest), Times.Once);
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies that validated request is passed to processor.
    /// Tests data flow from validator to processor.
    /// Critical for correct token revocation.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldPassValidatedRequestToProcessor()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidRevocationRequest(revocationRequest);
        var tokenRevoked = CreateTokenRevoked();

        _validator
            .Setup(v => v.ValidateAsync(revocationRequest, clientRequest))
            .ReturnsAsync(Result<ValidRevocationRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(It.Is<ValidRevocationRequest>(r => r == validRequest)))
            .ReturnsAsync(Result<TokenRevoked, OidcError>.Success(tokenRevoked));

        // Act
        await _handler.HandleAsync(revocationRequest, clientRequest);

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
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidRevocationRequest(revocationRequest);
        var tokenRevoked = CreateTokenRevoked();

        var callOrder = new System.Collections.Generic.List<string>();

        _validator
            .Setup(v => v.ValidateAsync(revocationRequest, clientRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("validate");
                return Result<ValidRevocationRequest, OidcError>.Success(validRequest);
            });

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("process");
                return Result<TokenRevoked, OidcError>.Success(tokenRevoked);
            });

        // Act
        await _handler.HandleAsync(revocationRequest, clientRequest);

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
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(
            ErrorCodes.InvalidGrant,
            "Token is invalid");

        _validator
            .Setup(v => v.ValidateAsync(revocationRequest, clientRequest))
            .ReturnsAsync(Result<ValidRevocationRequest, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.NotNull(failure.Error);
        Assert.NotEmpty(failure.Error);
        Assert.Equal(ErrorCodes.InvalidGrant, failure.Error);
    }

    /// <summary>
    /// Verifies that validator is called with correct parameters.
    /// Tests that both revocationRequest and clientRequest are passed to validator.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldCallValidatorWithBothRequests()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(ErrorCodes.InvalidRequest, "Invalid request");

        _validator
            .Setup(v => v.ValidateAsync(revocationRequest, clientRequest))
            .ReturnsAsync(Result<ValidRevocationRequest, OidcError>.Failure(error));

        // Act
        await _handler.HandleAsync(revocationRequest, clientRequest);

        // Assert
        _validator.Verify(
            v => v.ValidateAsync(
                It.Is<RevocationRequest>(r => r == revocationRequest),
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
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(ErrorCodes.InvalidClient, "Client not authorized");

        _validator
            .Setup(v => v.ValidateAsync(revocationRequest, clientRequest))
            .ReturnsAsync(Result<ValidRevocationRequest, OidcError>.Failure(error));

        // Act
        await _handler.HandleAsync(revocationRequest, clientRequest);

        // Assert
        _processor.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies revocation response includes token ID.
    /// Per RFC 7009, successful revocation returns information about revoked token.
    /// </summary>
    [Fact]
    public async Task HandleAsync_OnSuccess_ShouldReturnTokenId()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidRevocationRequest(revocationRequest);
        var tokenRevoked = CreateTokenRevoked();

        _validator
            .Setup(v => v.ValidateAsync(revocationRequest, clientRequest))
            .ReturnsAsync(Result<ValidRevocationRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<TokenRevoked, OidcError>.Success(tokenRevoked));

        // Act
        var result = await _handler.HandleAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var revoked));
        Assert.NotNull(revoked.TokenId);
        Assert.Equal("token_id_123", revoked.TokenId);
    }

    /// <summary>
    /// Verifies revocation includes timestamp.
    /// Tests that revocation time is recorded.
    /// </summary>
    [Fact]
    public async Task HandleAsync_OnSuccess_ShouldIncludeRevocationTimestamp()
    {
        // Arrange
        var revocationRequest = CreateRevocationRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidRevocationRequest(revocationRequest);
        var tokenRevoked = CreateTokenRevoked();

        _validator
            .Setup(v => v.ValidateAsync(revocationRequest, clientRequest))
            .ReturnsAsync(Result<ValidRevocationRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<TokenRevoked, OidcError>.Success(tokenRevoked));

        // Act
        var result = await _handler.HandleAsync(revocationRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var revoked));
        Assert.NotEqual(default, revoked.RevokedAt);
    }
}
