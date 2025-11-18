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
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.UserInfo;

/// <summary>
/// Unit tests for <see cref="UserInfoHandler"/> verifying request orchestration
/// (validate → process) per OIDC Core UserInfo Endpoint specification.
/// </summary>
public class UserInfoHandlerTests
{
    private readonly Mock<IUserInfoRequestValidator> _validator;
    private readonly Mock<IUserInfoRequestProcessor> _processor;
    private readonly UserInfoHandler _handler;

    public UserInfoHandlerTests()
    {
        _validator = new Mock<IUserInfoRequestValidator>(MockBehavior.Strict);
        _processor = new Mock<IUserInfoRequestProcessor>(MockBehavior.Strict);
        _handler = new UserInfoHandler(_validator.Object, _processor.Object);
    }

    private static UserInfoRequest CreateUserInfoRequest() => new()
    {
        AccessToken = "access_token_value",
    };

    private static ClientRequest CreateClientRequest() => new()
    {
        ClientId = "client_123",
    };

    private static ValidUserInfoRequest CreateValidUserInfoRequest(UserInfoRequest request)
    {
        var authSession = new Abblix.Oidc.Server.Features.UserAuthentication.AuthSession(
            "user_123",
            "session_123",
            DateTimeOffset.UtcNow,
            "local");

        var authContext = new Abblix.Oidc.Server.Common.AuthorizationContext(
            "client_123",
            ["openid", "profile"],
            null);

        var clientInfo = new ClientInfo("client_123");

        return new ValidUserInfoRequest(request, authSession, authContext, clientInfo);
    }

    private static UserInfoFoundResponse CreateUserInfoFoundResponse()
    {
        var user = new JsonObject
        {
            ["sub"] = "user_123",
            ["name"] = "John Doe",
            ["email"] = "john@example.com"
        };

        return new UserInfoFoundResponse(
            user,
            new ClientInfo("client_123"),
            "https://issuer.example.com");
    }

    /// <summary>
    /// Verifies successful UserInfo flow: validate → process.
    /// Tests happy path where validation and processing both succeed.
    /// </summary>
    [Fact]
    public async Task HandleAsync_SuccessfulFlow_ShouldReturnUserInfo()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidUserInfoRequest(userInfoRequest);
        var userInfoFound = CreateUserInfoFoundResponse();

        _validator
            .Setup(v => v.ValidateAsync(userInfoRequest, clientRequest))
            .ReturnsAsync(Result<ValidUserInfoRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<UserInfoFoundResponse, OidcError>.Success(userInfoFound));

        // Act
        var result = await _handler.HandleAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.Same(userInfoFound, response);
        _validator.Verify(v => v.ValidateAsync(userInfoRequest, clientRequest), Times.Once);
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies validation error handling.
    /// Per OIDC Core, validation errors should return error response without processing.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ValidationError_ShouldReturnError()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(
            ErrorCodes.InvalidGrant,
            "Access token is invalid or expired");

        _validator
            .Setup(v => v.ValidateAsync(userInfoRequest, clientRequest))
            .ReturnsAsync(Result<ValidUserInfoRequest, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
        _validator.Verify(v => v.ValidateAsync(userInfoRequest, clientRequest), Times.Once);
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
        var userInfoRequest = CreateUserInfoRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidUserInfoRequest(userInfoRequest);
        var error = new OidcError(
            ErrorCodes.ServerError,
            "Failed to retrieve user information");

        _validator
            .Setup(v => v.ValidateAsync(userInfoRequest, clientRequest))
            .ReturnsAsync(Result<ValidUserInfoRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<UserInfoFoundResponse, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
        _validator.Verify(v => v.ValidateAsync(userInfoRequest, clientRequest), Times.Once);
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies that validated request is passed to processor.
    /// Tests data flow from validator to processor.
    /// Critical for correct user info retrieval.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldPassValidatedRequestToProcessor()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidUserInfoRequest(userInfoRequest);
        var userInfoFound = CreateUserInfoFoundResponse();

        _validator
            .Setup(v => v.ValidateAsync(userInfoRequest, clientRequest))
            .ReturnsAsync(Result<ValidUserInfoRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(It.Is<ValidUserInfoRequest>(r => r == validRequest)))
            .ReturnsAsync(Result<UserInfoFoundResponse, OidcError>.Success(userInfoFound));

        // Act
        await _handler.HandleAsync(userInfoRequest, clientRequest);

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
        var userInfoRequest = CreateUserInfoRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidUserInfoRequest(userInfoRequest);
        var userInfoFound = CreateUserInfoFoundResponse();

        var callOrder = new System.Collections.Generic.List<string>();

        _validator
            .Setup(v => v.ValidateAsync(userInfoRequest, clientRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("validate");
                return Result<ValidUserInfoRequest, OidcError>.Success(validRequest);
            });

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("process");
                return Result<UserInfoFoundResponse, OidcError>.Success(userInfoFound);
            });

        // Act
        await _handler.HandleAsync(userInfoRequest, clientRequest);

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
        var userInfoRequest = CreateUserInfoRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(
            ErrorCodes.InvalidGrant,
            "Access token is invalid");

        _validator
            .Setup(v => v.ValidateAsync(userInfoRequest, clientRequest))
            .ReturnsAsync(Result<ValidUserInfoRequest, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.NotNull(failure.Error);
        Assert.NotEmpty(failure.Error);
        Assert.Equal(ErrorCodes.InvalidGrant, failure.Error);
    }

    /// <summary>
    /// Verifies that validator is called with correct parameters.
    /// Tests that both userInfoRequest and clientRequest are passed to validator.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldCallValidatorWithBothRequests()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(ErrorCodes.InvalidRequest, "Invalid request");

        _validator
            .Setup(v => v.ValidateAsync(userInfoRequest, clientRequest))
            .ReturnsAsync(Result<ValidUserInfoRequest, OidcError>.Failure(error));

        // Act
        await _handler.HandleAsync(userInfoRequest, clientRequest);

        // Assert
        _validator.Verify(
            v => v.ValidateAsync(
                It.Is<UserInfoRequest>(r => r == userInfoRequest),
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
        var userInfoRequest = CreateUserInfoRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(ErrorCodes.InvalidGrant, "Token not authorized");

        _validator
            .Setup(v => v.ValidateAsync(userInfoRequest, clientRequest))
            .ReturnsAsync(Result<ValidUserInfoRequest, OidcError>.Failure(error));

        // Act
        await _handler.HandleAsync(userInfoRequest, clientRequest);

        // Assert
        _processor.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies UserInfo response includes user claims.
    /// Per OIDC Core, successful response contains user claims.
    /// </summary>
    [Fact]
    public async Task HandleAsync_OnSuccess_ShouldReturnUserClaims()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidUserInfoRequest(userInfoRequest);
        var userInfoFound = CreateUserInfoFoundResponse();

        _validator
            .Setup(v => v.ValidateAsync(userInfoRequest, clientRequest))
            .ReturnsAsync(Result<ValidUserInfoRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<UserInfoFoundResponse, OidcError>.Success(userInfoFound));

        // Act
        var result = await _handler.HandleAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.NotNull(response.User);
        Assert.Equal("user_123", response.User["sub"]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies UserInfo response includes issuer.
    /// Per OIDC Core, response should include issuer identifier.
    /// </summary>
    [Fact]
    public async Task HandleAsync_OnSuccess_ShouldReturnIssuer()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidUserInfoRequest(userInfoRequest);
        var userInfoFound = CreateUserInfoFoundResponse();

        _validator
            .Setup(v => v.ValidateAsync(userInfoRequest, clientRequest))
            .ReturnsAsync(Result<ValidUserInfoRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<UserInfoFoundResponse, OidcError>.Success(userInfoFound));

        // Act
        var result = await _handler.HandleAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.NotNull(response.Issuer);
        Assert.Equal("https://issuer.example.com", response.Issuer);
    }
}
