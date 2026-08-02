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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.UserInfo;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.UserInfo;

/// <summary>
/// Unit tests for <see cref="UserInfoRequestValidator"/> verifying user info request
/// validation per OIDC Core specification.
/// </summary>
public class UserInfoRequestValidatorTests
{
    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator;
    private readonly Mock<IAccessTokenService> _accessTokenService;
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly Mock<IDPoPUserInfoValidator> _dpopValidator;
    private readonly Mock<IMtlsUserInfoValidator> _mtlsValidator;
    private readonly UserInfoRequestValidator _validator;

    public UserInfoRequestValidatorTests()
    {
        _jwtValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);
        _accessTokenService = new Mock<IAccessTokenService>(MockBehavior.Strict);
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        _dpopValidator = new Mock<IDPoPUserInfoValidator>(MockBehavior.Strict);
        _dpopValidator
            .Setup(v => v.ValidateAsync(It.IsAny<ClientRequest>(), It.IsAny<JsonWebToken>(), It.IsAny<string>()))
            .ReturnsAsync((OidcError?)null);
        _mtlsValidator = new Mock<IMtlsUserInfoValidator>(MockBehavior.Strict);
        _mtlsValidator
            .Setup(v => v.Validate(It.IsAny<ClientRequest>(), It.IsAny<JsonWebToken>()))
            .Returns((OidcError?)null);

        _validator = new UserInfoRequestValidator(
            _jwtValidator.Object,
            _accessTokenService.Object,
            _clientInfoProvider.Object,
            _dpopValidator.Object,
            _mtlsValidator.Object);
    }

    private static UserInfoRequest CreateUserInfoRequest(string? accessToken = null)
    {
        return new UserInfoRequest
        {
            AccessToken = accessToken,
        };
    }

    private static ClientRequest CreateClientRequest(
        string? clientId = null,
        AuthenticationHeaderValue? authHeader = null)
    {
        return new ClientRequest
        {
            ClientId = clientId,
            AuthorizationHeader = authHeader,
        };
    }

    private static JsonWebToken CreateValidAccessToken(string clientId = TestConstants.DefaultClientId)
    {
        var token = new JsonWebToken();
        token.Header.Type = JsonWebTokenTypes.AccessToken;
        token.Payload.ClientId = clientId;
        token.Payload.Subject = "user_123";
        token.Payload.JwtId = "jwt_id_123";
        return token;
    }

    private static AuthSession CreateAuthSession(string subject = "user_123")
    {
        return new AuthSession(
            Subject: subject,
            SessionId: "session_123",
            AuthenticationTime: DateTimeOffset.UtcNow,
            IdentityProvider: "local");
    }

    private static AuthorizationContext CreateAuthContext(string clientId = TestConstants.DefaultClientId)
    {
        return new AuthorizationContext(
            clientId: clientId,
            scope: [TestConstants.DefaultScope, "profile"],
            requestedClaims: null);
    }

    /// <summary>
    /// Verifies successful validation with valid token in Authorization header.
    /// Per OIDC Core, access token should be passed via Bearer scheme.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidTokenInHeader_ShouldReturnValidRequest()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest();
        var authHeader = new AuthenticationHeaderValue(TokenTypes.Bearer, "valid_token_123");
        var clientRequest = CreateClientRequest(authHeader: authHeader);

        var accessToken = CreateValidAccessToken();
        var authSession = CreateAuthSession();
        var authContext = CreateAuthContext();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "valid_token_123",
                It.Is<ValidationOptions>(o => (o & ~ValidationOptions.ValidateAudience) != 0)))
            .ReturnsAsync(accessToken);

        _accessTokenService
            .Setup(s => s.AuthenticateByAccessTokenAsync(accessToken, It.IsAny<ClientInfo>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)new AuthorizedGrant(authSession, authContext));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestConstants.DefaultClientId))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(userInfoRequest, validRequest.Model);
        Assert.Same(authSession, validRequest.AuthSession);
        Assert.Same(authContext, validRequest.AuthContext);
        Assert.Same(clientInfo, validRequest.ClientInfo);
    }

    /// <summary>
    /// Verifies successful validation with valid token in parameter.
    /// Per OIDC Core, access token can also be passed as a parameter.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidTokenInParameter_ShouldReturnValidRequest()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest("valid_token_123");
        var clientRequest = CreateClientRequest();

        var accessToken = CreateValidAccessToken();
        var authSession = CreateAuthSession();
        var authContext = CreateAuthContext();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "valid_token_123",
                It.Is<ValidationOptions>(o => (o & ~ValidationOptions.ValidateAudience) != 0)))
            .ReturnsAsync(accessToken);

        _accessTokenService
            .Setup(s => s.AuthenticateByAccessTokenAsync(accessToken, It.IsAny<ClientInfo>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)new AuthorizedGrant(authSession, authContext));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestConstants.DefaultClientId))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(userInfoRequest, validRequest.Model);
    }

    /// <summary>
    /// Verifies invalid scheme handling.
    /// Per OIDC Core, only Bearer scheme is supported for access tokens.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidScheme_ShouldReturnError()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest();
        var authHeader = new AuthenticationHeaderValue("Basic", "credentials");
        var clientRequest = CreateClientRequest(authHeader: authHeader);

        // Act
        var result = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        Assert.Contains("'Basic' is not supported", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when token provided in both header and parameter.
    /// Per specification, token should be in one location only.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithTokenInBothSources_ShouldReturnError()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest("token_in_param");
        var authHeader = new AuthenticationHeaderValue(TokenTypes.Bearer, "token_in_header");
        var clientRequest = CreateClientRequest(authHeader: authHeader);

        // Act
        var result = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        Assert.Contains("not in both sources", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when no token provided.
    /// Per OIDC Core, access token is required for UserInfo endpoint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoToken_ShouldReturnError()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest();
        var clientRequest = CreateClientRequest();

        // Act
        var result = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        Assert.Contains("none of them specified", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when Authorization header has no parameter.
    /// Bearer scheme requires a token parameter.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyHeaderParameter_ShouldReturnError()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest();
        var authHeader = new AuthenticationHeaderValue(TokenTypes.Bearer, null);
        var clientRequest = CreateClientRequest(authHeader: authHeader);

        // Act
        var result = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        Assert.Contains("must be specified", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies JWT validation error handling.
    /// Invalid access tokens should return error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidJwt_ShouldReturnError()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest("invalid_token");
        var clientRequest = CreateClientRequest();

        var validationError = new JwtValidationError(
            JwtError.InvalidToken,
            "Token is expired");

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "invalid_token",
                It.Is<ValidationOptions>(o => (o & ~ValidationOptions.ValidateAudience) != 0)))
            .ReturnsAsync(validationError);

        // Act
        var result = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        Assert.Equal("Token is expired", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies invalid token type handling.
    /// Per OIDC Core, only access tokens are valid for UserInfo endpoint.
    /// ID tokens or other token types should be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithInvalidTokenType_ShouldReturnError()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest("id_token_value");
        var clientRequest = CreateClientRequest();

        var idToken = CreateValidAccessToken();
        idToken.Header.Type = "id+jwt"; // Not an access token type

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "id_token_value",
                It.Is<ValidationOptions>(o => (o & ~ValidationOptions.ValidateAudience) != 0)))
            .ReturnsAsync(idToken);

        // Act
        var result = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        Assert.Contains("Invalid token type", error.ErrorDescription);
        Assert.Contains("id+jwt", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies client not found handling.
    /// If client associated with token doesn't exist, request should fail.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithClientNotFound_ShouldReturnError()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest("valid_token");
        var clientRequest = CreateClientRequest();

        var accessToken = CreateValidAccessToken("unknown_client");
        var authSession = CreateAuthSession();
        var authContext = CreateAuthContext("unknown_client");

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                "valid_token",
                It.Is<ValidationOptions>(o => (o & ~ValidationOptions.ValidateAudience) != 0)))
            .ReturnsAsync(accessToken);

        _accessTokenService
            .Setup(s => s.AuthenticateByAccessTokenAsync(accessToken, It.IsAny<ClientInfo>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)new AuthorizedGrant(authSession, authContext));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync("unknown_client"))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        Assert.Contains("'unknown_client' is not found", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies JWT validation uses correct validation options.
    /// The audience is checked here because this endpoint is a protected resource
    /// (OpenID Connect Core 1.0 Section 1.2), which puts it under RFC 9068 Section 4: "The resource server
    /// MUST validate that the aud claim contains a resource indicator value corresponding to an identifier
    /// the resource server expects for itself." Section 5 names the cost of skipping it - a token minted for
    /// another resource would open this one, which is the cross-JWT confusion distinct audiences exist to
    /// prevent.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldValidateJwtWithAudienceCheck()
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest("token_123");
        var clientRequest = CreateClientRequest();

        var accessToken = CreateValidAccessToken();
        var authSession = CreateAuthSession();
        var authContext = CreateAuthContext();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        ValidationOptions? capturedOptions = null;
        _jwtValidator
            .Setup(v => v.ValidateAsync("token_123", It.IsAny<ValidationOptions>()))
            .Callback(new Action<string, ValidationOptions>((_, options) => capturedOptions = options))
            .ReturnsAsync(accessToken);

        _accessTokenService
            .Setup(s => s.AuthenticateByAccessTokenAsync(accessToken, It.IsAny<ClientInfo>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)new AuthorizedGrant(authSession, authContext));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestConstants.DefaultClientId))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(userInfoRequest, clientRequest);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.Equal(
            ValidationOptions.RequireValidAudience,
            capturedOptions.Value & ValidationOptions.RequireValidAudience);
    }

    /// <summary>
    /// Both spellings of the access-token media type are accepted, per RFC 9068 Section 4: "The resource
    /// server MUST verify that the 'typ' header value is 'at+jwt' or 'application/at+jwt' and reject tokens
    /// carrying any other value." RFC 7515 Section 4.1.9 is why there are two of them: a recipient treats a
    /// value with no '/' as though 'application/' were prepended, so the short and long forms name one type
    /// rather than two.
    /// </summary>
    [Theory]
    [InlineData(JsonWebTokenTypes.AccessToken)]
    [InlineData("application/" + JsonWebTokenTypes.AccessToken)]
    [InlineData("Application/AT+JWT")]
    public async Task ValidateAsync_AcceptsEitherSpellingOfTheAccessTokenType(string tokenType)
    {
        var userInfoRequest = CreateUserInfoRequest();
        var authHeader = new AuthenticationHeaderValue(TokenTypes.Bearer, "valid_token_123");
        var clientRequest = CreateClientRequest(authHeader: authHeader);

        var accessToken = CreateValidAccessToken();
        accessToken.Header.Type = tokenType;
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _jwtValidator
            .Setup(v => v.ValidateAsync("valid_token_123", It.IsAny<ValidationOptions>()))
            .ReturnsAsync(accessToken);

        _accessTokenService
            .Setup(service => service.AuthenticateByAccessTokenAsync(accessToken, It.IsAny<ClientInfo>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)new AuthorizedGrant(
                CreateAuthSession(), CreateAuthContext()));

        _clientInfoProvider
            .Setup(provider => provider.TryFindClientAsync(TestConstants.DefaultClientId))
            .ReturnsAsync(clientInfo);

        var result = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        Assert.True(result.TryGetSuccess(out _), $"'{tokenType}' names the access-token media type");
    }

    /// <summary>
    /// Widening the accepted spelling must not widen the accepted set of token types: a token of another
    /// type is still refused, which is the RFC 8725 Section 3.11 token-type confusion guard the check exists
    /// for.
    /// </summary>
    [Theory]
    [InlineData(JwtTypes.RefreshToken)]
    [InlineData("application/jwt")]
    [InlineData("at+jwt-but-not-really")]
    public async Task ValidateAsync_ForeignTokenType_IsRejected(string tokenType)
    {
        var userInfoRequest = CreateUserInfoRequest();
        var authHeader = new AuthenticationHeaderValue(TokenTypes.Bearer, "valid_token_123");
        var clientRequest = CreateClientRequest(authHeader: authHeader);

        var accessToken = CreateValidAccessToken();
        accessToken.Header.Type = tokenType;

        _jwtValidator
            .Setup(v => v.ValidateAsync("valid_token_123", It.IsAny<ValidationOptions>()))
            .ReturnsAsync(accessToken);

        var result = await _validator.ValidateAsync(userInfoRequest, clientRequest);

        Assert.True(result.TryGetFailure(out var error), $"'{tokenType}' is not an access token");
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
    }
}
