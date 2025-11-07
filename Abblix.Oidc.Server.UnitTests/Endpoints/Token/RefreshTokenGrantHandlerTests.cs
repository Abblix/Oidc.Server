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
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="RefreshTokenGrantHandler"/> verifying the refresh_token grant type
/// as defined in RFC 6749 section 6.
/// Tests cover token validation, client ownership verification, token type checking, and error conditions.
/// </summary>
public class RefreshTokenGrantHandlerTests
{
    private const string ClientId = "test_client_123";
    private const string DifferentClientId = "different_client_456";
    private const string ValidRefreshToken = "valid.refresh.token";

    private readonly Mock<IParameterValidator> _parameterValidator;
    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator;
    private readonly Mock<IRefreshTokenService> _refreshTokenService;
    private readonly RefreshTokenGrantHandler _handler;

    public RefreshTokenGrantHandlerTests()
    {
        _parameterValidator = new Mock<IParameterValidator>(MockBehavior.Strict);
        _jwtValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);
        _refreshTokenService = new Mock<IRefreshTokenService>(MockBehavior.Strict);

        _handler = new RefreshTokenGrantHandler(
            _parameterValidator.Object,
            _jwtValidator.Object,
            _refreshTokenService.Object);
    }

    /// <summary>
    /// Verifies that a valid refresh token from the correct client successfully issues a new access token.
    /// This is the standard refresh token flow.
    /// </summary>
    [Fact]
    public async Task ValidRefreshToken_ShouldReturnNewGrant()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { RefreshToken = ValidRefreshToken };
        var refreshToken = CreateValidRefreshToken(ClientId);

        _parameterValidator.Setup(v => v.Required(tokenRequest.RefreshToken, nameof(tokenRequest.RefreshToken)));

        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidRefreshToken, ValidationOptions.Default))
            .ReturnsAsync(new ValidJsonWebToken(refreshToken));

        var expectedGrant = new AuthorizedGrant(
            new AuthSession("user123", "session1", DateTimeOffset.UtcNow, "192.168.1.1"),
            Context: new AuthorizationContext(ClientId, [Scopes.OpenId], null));

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(refreshToken))
            .ReturnsAsync(expectedGrant);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        Assert.Equal(ClientId, grant.Context.ClientId);
    }

    /// <summary>
    /// Verifies that when the refresh token belongs to a different client, the request is rejected.
    /// This prevents token theft attacks where one client tries to use another client's refresh token.
    /// </summary>
    [Fact]
    public async Task RefreshToken_BelongsToDifferentClient_ShouldReturnError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { RefreshToken = ValidRefreshToken };
        var refreshToken = CreateValidRefreshToken(ClientId);

        _parameterValidator.Setup(v => v.Required(tokenRequest.RefreshToken, nameof(tokenRequest.RefreshToken)));

        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidRefreshToken, ValidationOptions.Default))
            .ReturnsAsync(new ValidJsonWebToken(refreshToken));

        // Token belongs to different client
        var grantForDifferentClient = new AuthorizedGrant(
            new AuthSession("user123", "session1", DateTimeOffset.UtcNow, "192.168.1.1"),
            Context: new AuthorizationContext(DifferentClientId, [Scopes.OpenId], null));

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(refreshToken))
            .ReturnsAsync(grantForDifferentClient);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("another client", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that when an access token is provided instead of a refresh token, the request is rejected.
    /// The handler must validate that the token type is specifically 'refresh_token'.
    /// </summary>
    [Fact]
    public async Task WrongTokenType_AccessToken_ShouldReturnError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { RefreshToken = ValidRefreshToken };
        var accessToken = CreateTokenWithType(JwtTypes.AccessToken);

        _parameterValidator.Setup(v => v.Required(tokenRequest.RefreshToken, nameof(tokenRequest.RefreshToken)));

        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidRefreshToken, ValidationOptions.Default))
            .ReturnsAsync(new ValidJsonWebToken(accessToken));

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("Invalid token type", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that when an ID token is provided instead of a refresh token, the request is rejected.
    /// </summary>
    [Fact]
    public async Task WrongTokenType_IdToken_ShouldReturnError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { RefreshToken = ValidRefreshToken };
        var idToken = CreateTokenWithType("JWT");

        _parameterValidator.Setup(v => v.Required(tokenRequest.RefreshToken, nameof(tokenRequest.RefreshToken)));

        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidRefreshToken, ValidationOptions.Default))
            .ReturnsAsync(new ValidJsonWebToken(idToken));

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("Invalid token type", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that a malformed JWT results in an invalid_grant error.
    /// </summary>
    [Fact]
    public async Task MalformedJwt_ShouldReturnError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { RefreshToken = "malformed.jwt" };

        _parameterValidator.Setup(v => v.Required(tokenRequest.RefreshToken, nameof(tokenRequest.RefreshToken)));

        _jwtValidator
            .Setup(v => v.ValidateAsync("malformed.jwt", ValidationOptions.Default))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Token is malformed"));

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("Token is malformed", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that an expired refresh token results in an invalid_grant error.
    /// </summary>
    [Fact]
    public async Task ExpiredRefreshToken_ShouldReturnError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { RefreshToken = ValidRefreshToken };

        _parameterValidator.Setup(v => v.Required(tokenRequest.RefreshToken, nameof(tokenRequest.RefreshToken)));

        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidRefreshToken, ValidationOptions.Default))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Token has expired"));

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("Token has expired", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that when the refresh token service returns an error (e.g., token revoked),
    /// the error is properly propagated.
    /// </summary>
    [Fact]
    public async Task RefreshTokenService_ReturnsError_ShouldPropagateError()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { RefreshToken = ValidRefreshToken };
        var refreshToken = CreateValidRefreshToken(ClientId);

        _parameterValidator.Setup(v => v.Required(tokenRequest.RefreshToken, nameof(tokenRequest.RefreshToken)));

        _jwtValidator
            .Setup(v => v.ValidateAsync(ValidRefreshToken, ValidationOptions.Default))
            .ReturnsAsync(new ValidJsonWebToken(refreshToken));

        var serviceError = new OidcError(ErrorCodes.InvalidGrant, "Token has been revoked");
        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(refreshToken))
            .ReturnsAsync(serviceError);

        // Act
        var result = await _handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("Token has been revoked", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies that the handler reports the correct supported grant type.
    /// </summary>
    [Fact]
    public void GrantTypesSupported_ShouldReturnRefreshToken()
    {
        // Act
        var grantTypes = _handler.GrantTypesSupported.ToArray();

        // Assert
        Assert.Single(grantTypes);
        Assert.Equal(GrantTypes.RefreshToken, grantTypes[0]);
    }

    /// <summary>
    /// Creates a valid refresh token JWT with the specified client ID.
    /// </summary>
    private static JsonWebToken CreateValidRefreshToken(string clientId)
    {
        return new JsonWebToken
        {
            Header = { Type = JwtTypes.RefreshToken, Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Issuer = "https://issuer.example.com",
                Subject = "user123",
                ClientId = clientId,
                Audiences = ["test-audience"],
                IssuedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(30),
            },
        };
    }

    /// <summary>
    /// Creates a JWT with a specific token type.
    /// </summary>
    private static JsonWebToken CreateTokenWithType(string tokenType)
    {
        return new JsonWebToken
        {
            Header = { Type = tokenType, Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Issuer = "https://issuer.example.com",
                Subject = "user123",
                Audiences = ["test-audience"],
                IssuedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            },
        };
    }
}
