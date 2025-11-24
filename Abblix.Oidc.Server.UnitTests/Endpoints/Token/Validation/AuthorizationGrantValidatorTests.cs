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
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// Unit tests for <see cref="AuthorizationGrantValidator"/> verifying authorization grant validation
/// for token requests per OAuth 2.0 specification.
/// </summary>
public class AuthorizationGrantValidatorTests
{
    private readonly Mock<IAuthorizationGrantHandler> _grantHandler;
    private readonly AuthorizationGrantValidator _validator;

    public AuthorizationGrantValidatorTests()
    {
        _grantHandler = new Mock<IAuthorizationGrantHandler>(MockBehavior.Strict);
        _validator = new AuthorizationGrantValidator(_grantHandler.Object);
    }

    private static TokenValidationContext CreateContext(
        string grantType = GrantTypes.AuthorizationCode,
        Uri? redirectUri = null,
        string[]? allowedGrantTypes = null)
    {
        var tokenRequest = new TokenRequest
        {
            GrantType = grantType,
            RedirectUri = redirectUri,
        };
        var clientRequest = new ClientRequest();
        var context = new TokenValidationContext(tokenRequest, clientRequest);

        var clientInfo = new ClientInfo(TestConstants.DefaultClientId)
        {
            AllowedGrantTypes = allowedGrantTypes ?? [grantType],
        };
        context.ClientInfo = clientInfo;

        return context;
    }

    private static AuthorizedGrant CreateAuthorizedGrant(Uri? redirectUri = null)
    {
        var authSession = new AuthSession(
            Subject: "user_123",
            SessionId: "session_123",
            AuthenticationTime: DateTimeOffset.UtcNow,
            IdentityProvider: "local");

        var authContext = new AuthorizationContext(
            clientId: TestConstants.DefaultClientId,
            scope: ["openid"],
            requestedClaims: null)
        {
            RedirectUri = redirectUri,
        };

        return new AuthorizedGrant(authSession, authContext);
    }

    /// <summary>
    /// Verifies successful validation with matching redirect URIs and allowed grant type.
    /// Per OAuth 2.0, all conditions must be satisfied.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidGrant_ShouldSucceed()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/callback");
        var context = CreateContext(GrantTypes.AuthorizationCode, redirectUri);
        var authorizedGrant = CreateAuthorizedGrant(redirectUri);

        _grantHandler
            .Setup(h => h.AuthorizeAsync(It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>()))
            .ReturnsAsync(Result<AuthorizedGrant, OidcError>.Success(authorizedGrant));

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Same(authorizedGrant, context.AuthorizedGrant);
    }

    /// <summary>
    /// Verifies error when client not allowed to use grant type.
    /// Per OAuth 2.0, clients must be authorized for specific grant types.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenGrantTypeNotAllowed_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            grantType: GrantTypes.AuthorizationCode,
            allowedGrantTypes: [GrantTypes.ClientCredentials]);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.UnauthorizedClient, error.Error);
        Assert.Contains("grant type is not allowed", error.ErrorDescription);
        _grantHandler.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies error propagation from grant handler.
    /// Grant handler errors should be returned as-is.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenGrantHandlerFails_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext();
        var grantError = new OidcError(ErrorCodes.InvalidGrant, "Invalid authorization code");

        _grantHandler
            .Setup(h => h.AuthorizeAsync(It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>()))
            .ReturnsAsync(Result<AuthorizedGrant, OidcError>.Failure(grantError));

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Same(grantError, error);
    }

    /// <summary>
    /// Verifies error when redirect URI doesn't match.
    /// Per OAuth 2.0, redirect URI must match between authorization and token requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMismatchedRedirectUri_ShouldReturnError()
    {
        // Arrange
        var requestRedirectUri = new Uri("https://client.example.com/callback1");
        var grantRedirectUri = new Uri("https://client.example.com/callback2");
        var context = CreateContext(redirectUri: requestRedirectUri);
        var authorizedGrant = CreateAuthorizedGrant(grantRedirectUri);

        _grantHandler
            .Setup(h => h.AuthorizeAsync(It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>()))
            .ReturnsAsync(Result<AuthorizedGrant, OidcError>.Success(authorizedGrant));

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("redirect Uri value does not match", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies successful validation when both redirect URIs are null.
    /// Null redirect URIs should match.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithBothRedirectUrisNull_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(redirectUri: null);
        var authorizedGrant = CreateAuthorizedGrant(redirectUri: null);

        _grantHandler
            .Setup(h => h.AuthorizeAsync(It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>()))
            .ReturnsAsync(Result<AuthorizedGrant, OidcError>.Success(authorizedGrant));

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Same(authorizedGrant, context.AuthorizedGrant);
    }

    /// <summary>
    /// Verifies grant handler is called with correct parameters.
    /// Tests data flow from context to handler.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallGrantHandlerWithCorrectParameters()
    {
        // Arrange
        var context = CreateContext();
        var authorizedGrant = CreateAuthorizedGrant();

        _grantHandler
            .Setup(h => h.AuthorizeAsync(context.Request, context.ClientInfo))
            .ReturnsAsync(Result<AuthorizedGrant, OidcError>.Success(authorizedGrant));

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _grantHandler.Verify(h => h.AuthorizeAsync(context.Request, context.ClientInfo), Times.Once);
    }

    /// <summary>
    /// Verifies grant type check happens before grant handler call.
    /// Optimization: skip handler if grant type not allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCheckGrantTypeBeforeCallingHandler()
    {
        // Arrange
        var context = CreateContext(
            grantType: GrantTypes.RefreshToken,
            allowedGrantTypes: [GrantTypes.AuthorizationCode]);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _grantHandler.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies authorized grant is set in context on success.
    /// Downstream processors need access to authorized grant.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetAuthorizedGrantInContext()
    {
        // Arrange
        var context = CreateContext();
        var authorizedGrant = CreateAuthorizedGrant();

        _grantHandler
            .Setup(h => h.AuthorizeAsync(It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>()))
            .ReturnsAsync(Result<AuthorizedGrant, OidcError>.Success(authorizedGrant));

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Same(authorizedGrant, context.AuthorizedGrant);
    }

    /// <summary>
    /// Verifies multiple allowed grant types.
    /// Client can be authorized for multiple grant types.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleAllowedGrantTypes_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            grantType: GrantTypes.RefreshToken,
            allowedGrantTypes:
            [
                GrantTypes.AuthorizationCode,
                GrantTypes.RefreshToken,
                GrantTypes.ClientCredentials
            ]);
        var authorizedGrant = CreateAuthorizedGrant();

        _grantHandler
            .Setup(h => h.AuthorizeAsync(It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>()))
            .ReturnsAsync(Result<AuthorizedGrant, OidcError>.Success(authorizedGrant));

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies redirect URI case-sensitive comparison.
    /// Per RFC 3986, URIs are generally case-sensitive (except scheme and host).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldUseExactRedirectUriComparison()
    {
        // Arrange
        var requestRedirectUri = new Uri("https://client.example.com/Callback");
        var grantRedirectUri = new Uri("https://client.example.com/callback");
        var context = CreateContext(redirectUri: requestRedirectUri);
        var authorizedGrant = CreateAuthorizedGrant(grantRedirectUri);

        _grantHandler
            .Setup(h => h.AuthorizeAsync(It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>()))
            .ReturnsAsync(Result<AuthorizedGrant, OidcError>.Success(authorizedGrant));

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert - Path is case-sensitive
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
    }
}
