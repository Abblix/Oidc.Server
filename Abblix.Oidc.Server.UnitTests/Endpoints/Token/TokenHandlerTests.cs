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
using Abblix.Oidc.Server.Endpoints.Token;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="TokenHandler"/> verifying request orchestration
/// (validate → process) per OAuth 2.0/OIDC specifications.
/// </summary>
public class TokenHandlerTests
{
    private readonly Mock<ITokenRequestValidator> _validator;
    private readonly Mock<ITokenRequestProcessor> _processor;
    private readonly TokenHandler _handler;

    public TokenHandlerTests()
    {
        _validator = new Mock<ITokenRequestValidator>(MockBehavior.Strict);
        _processor = new Mock<ITokenRequestProcessor>(MockBehavior.Strict);
        _handler = new TokenHandler(_validator.Object, _processor.Object);
    }

    private static TokenRequest CreateTokenRequest() => new()
    {
        GrantType = GrantTypes.AuthorizationCode,
        Code = "auth_code_123",
        RedirectUri = new Uri("https://client.example.com/callback"),
    };

    private static ClientRequest CreateClientRequest() => new()
    {
        ClientId = TestConstants.DefaultClientId,
    };

    private static ValidTokenRequest CreateValidTokenRequest(TokenRequest tokenRequest) => new(
        tokenRequest,
        new AuthorizedGrant(
            new Abblix.Oidc.Server.Features.UserAuthentication.AuthSession(
                "user_123",
                "session_123",
                DateTimeOffset.UtcNow,
                "local"),
            new AuthorizationContext(
                TestConstants.DefaultClientId,
                [],
                null)),
        new ClientInfo(TestConstants.DefaultClientId),
        [],
        []);

    private static TokenIssued CreateTokenIssued()
    {
        var jwt = new Jwt.JsonWebToken();
        return new TokenIssued(
            new EncodedJsonWebToken(jwt, "access_token_jwt"),
            TokenTypes.Bearer,
            TimeSpan.FromHours(1),
            new Uri("urn:ietf:params:oauth:token-type:access_token"));
    }

    /// <summary>
    /// Verifies successful token flow: validate → process.
    /// Tests happy path where validation and processing both succeed.
    /// </summary>
    [Fact]
    public async Task HandleAsync_SuccessfulFlow_ShouldReturnTokenIssued()
    {
        // Arrange
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidTokenRequest(tokenRequest);
        var tokenIssued = CreateTokenIssued();

        _validator
            .Setup(v => v.ValidateAsync(tokenRequest, clientRequest))
            .ReturnsAsync(Result<ValidTokenRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<TokenIssued, OidcError>.Success(tokenIssued));

        // Act
        var result = await _handler.HandleAsync(tokenRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var issued));
        Assert.Same(tokenIssued, issued);
        _validator.Verify(v => v.ValidateAsync(tokenRequest, clientRequest), Times.Once);
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies validation error handling.
    /// Per OAuth 2.0, validation errors should return error response without processing.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ValidationError_ShouldReturnError()
    {
        // Arrange
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(
            ErrorCodes.InvalidGrant,
            "Authorization code is invalid or expired");

        _validator
            .Setup(v => v.ValidateAsync(tokenRequest, clientRequest))
            .ReturnsAsync(Result<ValidTokenRequest, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(tokenRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
        _validator.Verify(v => v.ValidateAsync(tokenRequest, clientRequest), Times.Once);
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
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidTokenRequest(tokenRequest);
        var error = new OidcError(
            ErrorCodes.ServerError,
            "Failed to issue token");

        _validator
            .Setup(v => v.ValidateAsync(tokenRequest, clientRequest))
            .ReturnsAsync(Result<ValidTokenRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(Result<TokenIssued, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(tokenRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
        _validator.Verify(v => v.ValidateAsync(tokenRequest, clientRequest), Times.Once);
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies that validated request is passed to processor.
    /// Tests data flow from validator to processor.
    /// Critical for correct token issuance.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldPassValidatedRequestToProcessor()
    {
        // Arrange
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidTokenRequest(tokenRequest);
        var tokenIssued = CreateTokenIssued();

        _validator
            .Setup(v => v.ValidateAsync(tokenRequest, clientRequest))
            .ReturnsAsync(Result<ValidTokenRequest, OidcError>.Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(It.Is<ValidTokenRequest>(r => r == validRequest)))
            .ReturnsAsync(Result<TokenIssued, OidcError>.Success(tokenIssued));

        // Act
        await _handler.HandleAsync(tokenRequest, clientRequest);

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
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        var validRequest = CreateValidTokenRequest(tokenRequest);
        var tokenIssued = CreateTokenIssued();

        var callOrder = new System.Collections.Generic.List<string>();

        _validator
            .Setup(v => v.ValidateAsync(tokenRequest, clientRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("validate");
                return Result<ValidTokenRequest, OidcError>.Success(validRequest);
            });

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("process");
                return Result<TokenIssued, OidcError>.Success(tokenIssued);
            });

        // Act
        await _handler.HandleAsync(tokenRequest, clientRequest);

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
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(
            ErrorCodes.InvalidClient,
            "Client authentication failed");

        _validator
            .Setup(v => v.ValidateAsync(tokenRequest, clientRequest))
            .ReturnsAsync(Result<ValidTokenRequest, OidcError>.Failure(error));

        // Act
        var result = await _handler.HandleAsync(tokenRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.NotNull(failure.Error);
        Assert.NotEmpty(failure.Error);
        Assert.Equal(ErrorCodes.InvalidClient, failure.Error);
    }

    /// <summary>
    /// Verifies that validator is called with correct parameters.
    /// Tests that both tokenRequest and clientRequest are passed to validator.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldCallValidatorWithBothRequests()
    {
        // Arrange
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(ErrorCodes.InvalidRequest, "Invalid request");

        _validator
            .Setup(v => v.ValidateAsync(tokenRequest, clientRequest))
            .ReturnsAsync(Result<ValidTokenRequest, OidcError>.Failure(error));

        // Act
        await _handler.HandleAsync(tokenRequest, clientRequest);

        // Assert
        _validator.Verify(
            v => v.ValidateAsync(
                It.Is<TokenRequest>(r => r == tokenRequest),
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
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(ErrorCodes.InvalidGrant, "Invalid authorization code");

        _validator
            .Setup(v => v.ValidateAsync(tokenRequest, clientRequest))
            .ReturnsAsync(Result<ValidTokenRequest, OidcError>.Failure(error));

        // Act
        await _handler.HandleAsync(tokenRequest, clientRequest);

        // Assert
        _processor.VerifyNoOtherCalls();
    }
}
