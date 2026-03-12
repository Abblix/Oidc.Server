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
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="InitialAccessTokenValidator"/> verifying initial access token
/// validation per RFC 7591 Section 3 and RFC 6750 Bearer Token Usage.
/// </summary>
public class InitialAccessTokenValidatorTests
{
    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator;
    private readonly Mock<IInitialAccessTokenRevocationProvider> _revocationProvider;
    private readonly OidcOptions _options;
    private readonly InitialAccessTokenValidator _validator;

    public InitialAccessTokenValidatorTests()
    {
        _jwtValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);
        _revocationProvider = new Mock<IInitialAccessTokenRevocationProvider>(MockBehavior.Strict);
        _options = new OidcOptions { RequireInitialAccessToken = true };

        var optionsMonitor = new Mock<IOptionsMonitor<OidcOptions>>();
        optionsMonitor.Setup(m => m.CurrentValue).Returns(() => _options);

        _validator = new InitialAccessTokenValidator(
            _jwtValidator.Object,
            _revocationProvider.Object,
            optionsMonitor.Object);
    }

    private static ClientRegistrationValidationContext CreateContext(
        AuthenticationHeaderValue? authHeader = null,
        DynamicClientOperation operation = DynamicClientOperation.Register)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            AuthorizationHeader = authHeader,
        };

        return new ClientRegistrationValidationContext(request) { Operation = operation };
    }

    private static JsonWebToken CreateValidToken(string tokenType = JwtTypes.InitialAccessToken, string? subject = "registration-portal")
    {
        var token = new JsonWebToken();
        token.Header.Type = tokenType;
        token.Payload.Subject = subject;
        return token;
    }

    [Fact]
    public async Task ValidateAsync_WhenFeatureDisabled_ShouldSkip()
    {
        _options.RequireInitialAccessToken = false;
        var context = CreateContext();

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WhenUpdateOperation_ShouldSkip()
    {
        var context = CreateContext(operation: DynamicClientOperation.Update);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WithNoAuthorizationHeader_ShouldReturnInvalidToken()
    {
        var context = CreateContext(authHeader: null);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidToken, result.Error);
        Assert.Contains("Authorization", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_WithWrongScheme_ShouldReturnInvalidToken()
    {
        var context = CreateContext(new AuthenticationHeaderValue("Basic", "credentials"));

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidToken, result.Error);
        Assert.Contains("Basic", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_WithInvalidJwt_ShouldReturnInvalidToken()
    {
        var context = CreateContext(new AuthenticationHeaderValue(TokenTypes.Bearer, "bad-jwt"));

        _jwtValidator
            .Setup(v => v.ValidateAsync("bad-jwt", It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Token is expired"));

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidToken, result.Error);
        Assert.Contains("expired", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_WithWrongTokenType_ShouldReturnInvalidToken()
    {
        var context = CreateContext(new AuthenticationHeaderValue(TokenTypes.Bearer, "jwt-token"));
        var token = CreateValidToken(tokenType: JwtTypes.AccessToken);

        _jwtValidator
            .Setup(v => v.ValidateAsync("jwt-token", It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidToken, result.Error);
        Assert.Contains("token type", result.ErrorDescription);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ValidateAsync_WithMissingSubject_ShouldReturnInvalidToken(string? subject)
    {
        var context = CreateContext(new AuthenticationHeaderValue(TokenTypes.Bearer, "jwt-token"));
        var token = CreateValidToken(subject: subject);

        _jwtValidator
            .Setup(v => v.ValidateAsync("jwt-token", It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidToken, result.Error);
        Assert.Contains("subject", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_WithRevokedToken_ShouldReturnInvalidToken()
    {
        var context = CreateContext(new AuthenticationHeaderValue(TokenTypes.Bearer, "jwt-token"));
        var token = CreateValidToken();

        _jwtValidator
            .Setup(v => v.ValidateAsync("jwt-token", It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        _revocationProvider
            .Setup(r => r.IsRevokedAsync("registration-portal"))
            .ReturnsAsync(true);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidToken, result.Error);
        Assert.Contains("revoked", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_WithValidToken_ShouldReturnNull()
    {
        var context = CreateContext(new AuthenticationHeaderValue(TokenTypes.Bearer, "valid-jwt"));
        var token = CreateValidToken();

        _jwtValidator
            .Setup(v => v.ValidateAsync("valid-jwt", It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        _revocationProvider
            .Setup(r => r.IsRevokedAsync("registration-portal"))
            .ReturnsAsync(false);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_ShouldSkipAudienceValidation()
    {
        var context = CreateContext(new AuthenticationHeaderValue(TokenTypes.Bearer, "jwt-token"));
        var token = CreateValidToken();

        ValidationOptions? capturedOptions = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync("jwt-token", It.IsAny<ValidationOptions>()))
            .Callback(new Action<string, ValidationOptions>((_, opts) => capturedOptions = opts))
            .ReturnsAsync(token);

        _revocationProvider
            .Setup(r => r.IsRevokedAsync("registration-portal"))
            .ReturnsAsync(false);

        await _validator.ValidateAsync(context);

        Assert.NotNull(capturedOptions);
        Assert.Equal(ValidationOptions.Default & ~ValidationOptions.ValidateAudience, capturedOptions);
    }
}
