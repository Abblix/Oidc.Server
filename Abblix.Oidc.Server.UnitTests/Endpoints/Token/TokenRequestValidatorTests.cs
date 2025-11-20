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
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="TokenRequestValidator"/> verifying composite validator
/// behavior implementing Chain of Responsibility pattern for token request validation.
/// </summary>
public class TokenRequestValidatorTests
{
    private readonly Mock<ITokenContextValidator> _contextValidator;
    private readonly TokenRequestValidator _validator;

    public TokenRequestValidatorTests()
    {
        _contextValidator = new Mock<ITokenContextValidator>(MockBehavior.Strict);
        _validator = new TokenRequestValidator(_contextValidator.Object);
    }

    private static TokenRequest CreateTokenRequest() => new()
    {
        GrantType = GrantTypes.AuthorizationCode,
        Code = "auth_code_123",
        RedirectUri = new Uri("https://client.example.com/callback"),
    };

    private static ClientRequest CreateClientRequest() => new()
    {
        ClientId = "client_123",
    };

    private static AuthorizedGrant CreateAuthorizedGrant() => new(
        new Abblix.Oidc.Server.Features.UserAuthentication.AuthSession(
            "user_123",
            "session_123",
            DateTimeOffset.UtcNow,
            "local"),
        new AuthorizationContext(
            "client_123",
            [],
            null));

    /// <summary>
    /// Verifies successful validation returns ValidTokenRequest.
    /// Tests happy path where context validator succeeds.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenContextValidatorSucceeds_ShouldReturnValidRequest()
    {
        // Arrange
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<TokenValidationContext>()))
            .Callback<TokenValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.AuthorizedGrant = CreateAuthorizedGrant();
                ctx.Scope = [];
                ctx.Resources = [];
            })
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(tokenRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(validRequest);
        Assert.Equal(tokenRequest.GrantType, validRequest.Model.GrantType);
    }

    /// <summary>
    /// Verifies validation error returns error response.
    /// Tests error propagation from context validator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenContextValidatorFails_ShouldReturnError()
    {
        // Arrange
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(
            ErrorCodes.InvalidGrant,
            "Authorization code is invalid or expired");

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<TokenValidationContext>()))
            .ReturnsAsync(error);

        // Act
        var result = await _validator.ValidateAsync(tokenRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(error, failure);
    }

    /// <summary>
    /// Verifies ValidateAsync creates TokenValidationContext correctly.
    /// Tests context creation with both token and client requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCreateContextWithBothRequests()
    {
        // Arrange
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        TokenValidationContext? capturedContext = null;

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<TokenValidationContext>()))
            .Callback<TokenValidationContext>(ctx =>
            {
                capturedContext = ctx;
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.AuthorizedGrant = CreateAuthorizedGrant();
                ctx.Scope = [];
                ctx.Resources = [];
            })
            .ReturnsAsync((OidcError?)null);

        // Act
        await _validator.ValidateAsync(tokenRequest, clientRequest);

        // Assert
        Assert.NotNull(capturedContext);
        Assert.Same(tokenRequest, capturedContext.Request);
        Assert.Same(clientRequest, capturedContext.ClientRequest);
    }

    /// <summary>
    /// Verifies ValidateAsync calls context validator exactly once.
    /// Tests efficient validation without redundant calls.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallContextValidatorOnce()
    {
        // Arrange
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<TokenValidationContext>()))
            .Callback<TokenValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.AuthorizedGrant = CreateAuthorizedGrant();
                ctx.Scope = [];
                ctx.Resources = [];
            })
            .ReturnsAsync((OidcError?)null);

        // Act
        await _validator.ValidateAsync(tokenRequest, clientRequest);

        // Assert
        _contextValidator.Verify(
            v => v.ValidateAsync(It.IsAny<TokenValidationContext>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies ValidateAsync wraps validated context in ValidTokenRequest.
    /// Tests correct transformation from context to valid request.
    /// Critical for downstream processing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldWrapContextInValidRequest()
    {
        // Arrange
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        TokenValidationContext? capturedContext = null;

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<TokenValidationContext>()))
            .Callback<TokenValidationContext>(ctx =>
            {
                capturedContext = ctx;
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.AuthorizedGrant = CreateAuthorizedGrant();
                ctx.Scope = [];
                ctx.Resources = [];
            })
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(tokenRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.NotNull(capturedContext);
        Assert.Same(capturedContext.Request, validRequest.Model);
        Assert.Same(capturedContext.ClientInfo, validRequest.ClientInfo);
        Assert.Same(capturedContext.AuthorizedGrant, validRequest.AuthorizedGrant);
    }

    /// <summary>
    /// Verifies ValidateAsync handles null error as success.
    /// Per design: null error indicates validation success.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenValidatorReturnsNull_ShouldSucceed()
    {
        // Arrange
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<TokenValidationContext>()))
            .Callback<TokenValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.AuthorizedGrant = CreateAuthorizedGrant();
                ctx.Scope = [];
                ctx.Resources = [];
            })
            .ReturnsAsync((OidcError?)null);

        // Act
        var result = await _validator.ValidateAsync(tokenRequest, clientRequest);

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
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        var error = new OidcError(
            ErrorCodes.InvalidClient,
            "Client authentication failed");

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<TokenValidationContext>()))
            .ReturnsAsync(error);

        // Act
        var result = await _validator.ValidateAsync(tokenRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var failure));
        Assert.Equal(ErrorCodes.InvalidClient, failure.Error);
        Assert.Equal("Client authentication failed", failure.ErrorDescription);
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
        var tokenRequest1 = CreateTokenRequest();
        var tokenRequest2 = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        var capturedContexts = new System.Collections.Generic.List<TokenValidationContext>();

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<TokenValidationContext>()))
            .Callback<TokenValidationContext>(ctx =>
            {
                capturedContexts.Add(ctx);
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.AuthorizedGrant = CreateAuthorizedGrant();
                ctx.Scope = [];
                ctx.Resources = [];
            })
            .ReturnsAsync((OidcError?)null);

        // Act
        await _validator.ValidateAsync(tokenRequest1, clientRequest);
        await _validator.ValidateAsync(tokenRequest2, clientRequest);

        // Assert
        Assert.Equal(2, capturedContexts.Count);
        Assert.NotSame(capturedContexts[0], capturedContexts[1]);
    }

    /// <summary>
    /// Verifies ValidateAsync with different grant types.
    /// Tests validator handles various grant type configurations.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentGrantTypes_ShouldValidateEach()
    {
        // Arrange
        var authCodeRequest = new TokenRequest
        {
            GrantType = GrantTypes.AuthorizationCode,
            Code = "auth_code_123",
            RedirectUri = new Uri("https://client.example.com/callback"),
        };

        var refreshTokenRequest = new TokenRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "refresh_token_123",
        };

        var clientRequest = CreateClientRequest();

        _contextValidator
            .Setup(v => v.ValidateAsync(It.IsAny<TokenValidationContext>()))
            .Callback<TokenValidationContext>(ctx =>
            {
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.AuthorizedGrant = CreateAuthorizedGrant();
                ctx.Scope = [];
                ctx.Resources = [];
            })
            .ReturnsAsync((OidcError?)null);

        // Act
        var result1 = await _validator.ValidateAsync(authCodeRequest, clientRequest);
        var result2 = await _validator.ValidateAsync(refreshTokenRequest, clientRequest);

        // Assert
        Assert.True(result1.TryGetSuccess(out var validRequest1));
        Assert.True(result2.TryGetSuccess(out var validRequest2));
        Assert.Equal(GrantTypes.AuthorizationCode, validRequest1.Model.GrantType);
        Assert.Equal(GrantTypes.RefreshToken, validRequest2.Model.GrantType);
        _contextValidator.Verify(
            v => v.ValidateAsync(It.IsAny<TokenValidationContext>()),
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
        var tokenRequest = CreateTokenRequest();
        var clientRequest = CreateClientRequest();
        TokenValidationContext? capturedContext = null;

        _contextValidator
            .Setup(v => v.ValidateAsync(It.Is<TokenValidationContext>(
                ctx => ctx.Request == tokenRequest && ctx.ClientRequest == clientRequest)))
            .Callback<TokenValidationContext>(ctx =>
            {
                capturedContext = ctx;
                ctx.ClientInfo = new ClientInfo("client_123");
                ctx.AuthorizedGrant = CreateAuthorizedGrant();
                ctx.Scope = [];
                ctx.Resources = [];
            })
            .ReturnsAsync((OidcError?)null);

        // Act
        await _validator.ValidateAsync(tokenRequest, clientRequest);

        // Assert
        Assert.NotNull(capturedContext);
        Assert.Same(tokenRequest, capturedContext.Request);
        Assert.Same(clientRequest, capturedContext.ClientRequest);
        _contextValidator.Verify(
            v => v.ValidateAsync(It.Is<TokenValidationContext>(
                ctx => ctx.Request == tokenRequest && ctx.ClientRequest == clientRequest)),
            Times.Once);
    }
}
