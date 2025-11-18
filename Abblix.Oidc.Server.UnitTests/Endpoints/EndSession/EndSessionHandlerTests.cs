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
using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession;

/// <summary>
/// Unit tests for <see cref="EndSessionHandler"/> verifying request orchestration
/// (validate → process) per OIDC Session Management specification.
/// </summary>
public class EndSessionHandlerTests
{
    private readonly Mock<IEndSessionRequestValidator> _validator;
    private readonly Mock<IEndSessionRequestProcessor> _processor;
    private readonly EndSessionHandler _handler;

    public EndSessionHandlerTests()
    {
        _validator = new Mock<IEndSessionRequestValidator>(MockBehavior.Strict);
        _processor = new Mock<IEndSessionRequestProcessor>(MockBehavior.Strict);
        _handler = new EndSessionHandler(_validator.Object, _processor.Object);
    }

    private static EndSessionRequest CreateEndSessionRequest() => new()
    {
        IdTokenHint = "id_token_hint_value",
        PostLogoutRedirectUri = new Uri("https://client.example.com/logout"),
        State = "state_123",
    };

    private static ValidEndSessionRequest CreateValidEndSessionRequest(EndSessionRequest request)
    {
        var clientInfo = new ClientInfo("client_123");
        return new ValidEndSessionRequest(request, clientInfo);
    }

    private static EndSessionSuccess CreateEndSessionSuccess()
    {
        var postLogoutRedirectUri = new Uri("https://client.example.com/logout");
        var frontChannelLogoutUris = new List<Uri>
        {
            new Uri("https://app1.example.com/logout"),
            new Uri("https://app2.example.com/logout"),
        };
        return new EndSessionSuccess(postLogoutRedirectUri, frontChannelLogoutUris);
    }

    /// <summary>
    /// Verifies successful EndSession flow: validate → process.
    /// Tests happy path where validation and processing both succeed.
    /// </summary>
    [Fact]
    public async Task HandleAsync_SuccessfulFlow_ShouldReturnEndSessionSuccess()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest();
        var validRequest = CreateValidEndSessionRequest(endSessionRequest);
        var endSessionSuccess = CreateEndSessionSuccess();

        _validator
            .Setup(v => v.ValidateAsync(endSessionRequest))
            .ReturnsAsync(Result<ValidEndSessionRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<EndSessionSuccess, OidcError>.Success(endSessionSuccess));

        // Act
        var result = await _handler.HandleAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.Same(endSessionSuccess, response);
        _validator.Verify(v => v.ValidateAsync(endSessionRequest), Times.Once);
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies validation error handling.
    /// Per OIDC Session Management, validation errors should return error response without processing.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ValidationError_ShouldReturnError()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest();
        var error = new OidcError(
            ErrorCodes.InvalidRequest,
            "Invalid id_token_hint");

        _validator
            .Setup(v => v.ValidateAsync(endSessionRequest))
            .ReturnsAsync(Result<ValidEndSessionRequest, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
        _validator.Verify(v => v.ValidateAsync(endSessionRequest), Times.Once);
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
        var endSessionRequest = CreateEndSessionRequest();
        var validRequest = CreateValidEndSessionRequest(endSessionRequest);
        var error = new OidcError(
            ErrorCodes.ServerError,
            "Failed to end session");

        _validator
            .Setup(v => v.ValidateAsync(endSessionRequest))
            .ReturnsAsync(Result<ValidEndSessionRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<EndSessionSuccess, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
        _validator.Verify(v => v.ValidateAsync(endSessionRequest), Times.Once);
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies that validated request is passed to processor.
    /// Tests data flow from validator to processor.
    /// Critical for correct logout handling.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldPassValidatedRequestToProcessor()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest();
        var validRequest = CreateValidEndSessionRequest(endSessionRequest);
        var endSessionSuccess = CreateEndSessionSuccess();

        _validator
            .Setup(v => v.ValidateAsync(endSessionRequest))
            .ReturnsAsync(Result<ValidEndSessionRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(It.Is<ValidEndSessionRequest>(r => r == validRequest)))
            .ReturnsAsync(Result<EndSessionSuccess, OidcError>.Success(endSessionSuccess));

        // Act
        await _handler.HandleAsync(endSessionRequest);

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
        var endSessionRequest = CreateEndSessionRequest();
        var validRequest = CreateValidEndSessionRequest(endSessionRequest);
        var endSessionSuccess = CreateEndSessionSuccess();

        var callOrder = new List<string>();

        _validator
            .Setup(v => v.ValidateAsync(endSessionRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("validate");
                return Result<ValidEndSessionRequest, OidcError>.Success(validRequest);
            });

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("process");
                return Result<EndSessionSuccess, OidcError>.Success(endSessionSuccess);
            });

        // Act
        await _handler.HandleAsync(endSessionRequest);

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
        var endSessionRequest = CreateEndSessionRequest();
        var error = new OidcError(
            ErrorCodes.InvalidRequest,
            "Invalid request");

        _validator
            .Setup(v => v.ValidateAsync(endSessionRequest))
            .ReturnsAsync(Result<ValidEndSessionRequest, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.NotNull(failure.Error);
        Assert.NotEmpty(failure.Error);
        Assert.Equal(ErrorCodes.InvalidRequest, failure.Error);
    }

    /// <summary>
    /// Verifies that validator is called with correct parameters.
    /// Tests that endSessionRequest is passed to validator.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldCallValidatorWithRequest()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest();
        var error = new OidcError(ErrorCodes.InvalidRequest, "Invalid request");

        _validator
            .Setup(v => v.ValidateAsync(endSessionRequest))
            .ReturnsAsync(Result<ValidEndSessionRequest, OidcError>.Failure(error));

        // Act
        await _handler.HandleAsync(endSessionRequest);

        // Assert
        _validator.Verify(
            v => v.ValidateAsync(It.Is<EndSessionRequest>(r => r == endSessionRequest)),
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
        var endSessionRequest = CreateEndSessionRequest();
        var error = new OidcError(ErrorCodes.InvalidRequest, "Validation failed");

        _validator
            .Setup(v => v.ValidateAsync(endSessionRequest))
            .ReturnsAsync(Result<ValidEndSessionRequest, OidcError>.Failure(error));

        // Act
        await _handler.HandleAsync(endSessionRequest);

        // Assert
        _processor.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies EndSession response includes post-logout redirect URI.
    /// Per OIDC Session Management, successful response may contain redirect URI.
    /// </summary>
    [Fact]
    public async Task HandleAsync_OnSuccess_ShouldReturnPostLogoutRedirectUri()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest();
        var validRequest = CreateValidEndSessionRequest(endSessionRequest);
        var endSessionSuccess = CreateEndSessionSuccess();

        _validator
            .Setup(v => v.ValidateAsync(endSessionRequest))
            .ReturnsAsync(Result<ValidEndSessionRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<EndSessionSuccess, OidcError>.Success(endSessionSuccess));

        // Act
        var result = await _handler.HandleAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.NotNull(response.PostLogoutRedirectUri);
        Assert.Equal("https://client.example.com/logout", response.PostLogoutRedirectUri.ToString());
    }

    /// <summary>
    /// Verifies EndSession response includes front-channel logout URIs.
    /// Per OIDC Front-Channel Logout, response should include logout URIs.
    /// </summary>
    [Fact]
    public async Task HandleAsync_OnSuccess_ShouldReturnFrontChannelLogoutUris()
    {
        // Arrange
        var endSessionRequest = CreateEndSessionRequest();
        var validRequest = CreateValidEndSessionRequest(endSessionRequest);
        var endSessionSuccess = CreateEndSessionSuccess();

        _validator
            .Setup(v => v.ValidateAsync(endSessionRequest))
            .ReturnsAsync(Result<ValidEndSessionRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<EndSessionSuccess, OidcError>.Success(endSessionSuccess));

        // Act
        var result = await _handler.HandleAsync(endSessionRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.NotNull(response.FrontChannelLogoutRequestUris);
        Assert.Equal(2, response.FrontChannelLogoutRequestUris.Count);
    }
}
