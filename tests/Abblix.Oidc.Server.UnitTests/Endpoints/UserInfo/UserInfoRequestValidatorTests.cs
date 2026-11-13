// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
using Abblix.Oidc.Server.Features.MultiTenancy;
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
            .Setup(v => v.ValidateAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<JsonWebToken>(), It.IsAny<string>()))
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

    private static UserInfoRequest CreateUserInfoRequest(string? inForm = null, string? inQuery = null)
    {
        return new UserInfoRequest
        {
            AccessTokenInForm = inForm,
            AccessTokenInQuery = inQuery,
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
            AuthenticationTime: TimeProvider.System.GetUtcNow(),
            IdentityProvider: "local");
    }

    private static AuthorizationContext CreateAuthContext(string clientId = TestConstants.DefaultClientId)
    {
        return new AuthorizationContext(
            clientId: clientId,
            scope: [TestConstants.DefaultScope, Scopes.Profile],
            requestedClaims: null);
    }

    public static TheoryData<string> SupportedSchemesInAnyCase() =>
    [
        TokenTypes.Bearer,
        TokenTypes.Bearer.ToLowerInvariant(),
        TokenTypes.DPoP,
        TokenTypes.DPoP.ToLowerInvariant(),
        TokenTypes.DPoP.ToUpperInvariant(),
    ];

    /// <summary>
    /// Verifies successful validation with valid token in Authorization header.
    /// Per OIDC Core, access token should be passed via Bearer scheme.
    /// </summary>
    /// <remarks>
    /// RFC 9110 section 11.1 identifies the scheme by a case-insensitive token, so either supported scheme in any case
    /// is accepted; the DPoP binding itself is the DPoP validator's to judge.
    /// </remarks>
    [Theory]
    [MemberData(nameof(SupportedSchemesInAnyCase))]
    public async Task ValidateAsync_WithValidTokenInHeader_ShouldReturnValidRequest(string scheme)
    {
        // Arrange
        var userInfoRequest = CreateUserInfoRequest();
        var authHeader = new AuthenticationHeaderValue(scheme, "valid_token_123");
        var clientRequest = CreateClientRequest(authHeader: authHeader);

        var accessToken = CreateValidAccessToken();
        var authSession = CreateAuthSession();
        var authContext = CreateAuthContext();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                TestTenant.Matched, "valid_token_123",
                It.IsAny<TokenTypePolicy>(), It.Is<ValidationOptions>(o => (o & ~ValidationOptions.ValidateAudience) != 0)))
            .ReturnsAsync(accessToken);

        _accessTokenService
            .Setup(s => s.AuthenticateByAccessTokenAsync(TestTenant.Matched, accessToken, It.IsAny<ClientInfo>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)new AuthorizedGrant(authSession, authContext));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, userInfoRequest, clientRequest);

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
                TestTenant.Matched, "valid_token_123",
                It.IsAny<TokenTypePolicy>(), It.Is<ValidationOptions>(o => (o & ~ValidationOptions.ValidateAudience) != 0)))
            .ReturnsAsync(accessToken);

        _accessTokenService
            .Setup(s => s.AuthenticateByAccessTokenAsync(TestTenant.Matched, accessToken, It.IsAny<ClientInfo>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)new AuthorizedGrant(authSession, authContext));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(userInfoRequest, validRequest.Model);
    }

    /// <summary>
    /// RFC 6750 section 3.1: "If the request lacks any authentication information (e.g., the client was unaware that
    /// authentication is necessary or attempted using an unsupported authentication method), the resource server
    /// SHOULD NOT include an error code or other error information." A scheme this endpoint does not speak is answered
    /// with the bare challenge a request with no credentials gets.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedScheme_IsAnsweredAsMissingAuthentication()
    {
        var userInfoRequest = CreateUserInfoRequest();
        var authHeader = new AuthenticationHeaderValue(TokenTypes.Basic, "credentials");
        var clientRequest = CreateClientRequest(authHeader: authHeader);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, userInfoRequest, clientRequest);

        Assert.True(result.TryGetFailure(out var error));
        Assert.IsType<MissingAuthenticationError>(error);
    }

    /// <summary>
    /// RFC 6750 section 3.1: a request that "uses more than one method for including an access token" is an
    /// invalid_request, so the token in the Authorization header and again as a parameter, of the body or of the
    /// query, is refused as one.
    /// </summary>
    /// <remarks>
    /// A header of a scheme this endpoint does not speak counts too: the request carries a token, so it does not lack
    /// authentication information and is not owed the bare challenge section 3.1 keeps for one that does.
    /// </remarks>
    [Theory]
    [InlineData(TokenTypes.Bearer, "token_in_param", null)]
    [InlineData(TokenTypes.Bearer, null, "token_in_param")]
    [InlineData(TokenTypes.Basic, "token_in_param", null)]
    [InlineData(TokenTypes.Basic, null, "token_in_param")]
    public async Task ValidateAsync_WithTokenInHeaderAndParameter_IsInvalidRequest(
        string scheme, string? inForm, string? inQuery)
    {
        var userInfoRequest = CreateUserInfoRequest(inForm, inQuery);
        var authHeader = new AuthenticationHeaderValue(scheme, "token_in_header");
        var clientRequest = CreateClientRequest(authHeader: authHeader);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, userInfoRequest, clientRequest);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        Assert.Contains("none of them specified", error.ErrorDescription);
    }

    /// <summary>
    /// RFC 6750 section 2.1 gives the credentials as <c>"Bearer" 1*SP b64token</c>, so a header naming the scheme
    /// without a token is a malformed request rather than a bad token, and section 3.1 names that invalid_request:
    /// "The request is missing a required parameter ... or is otherwise malformed."
    /// </summary>
    [Theory]
    [InlineData(TokenTypes.Bearer)]
    [InlineData(TokenTypes.DPoP)]
    public async Task ValidateAsync_WithSchemeButNoToken_IsInvalidRequest(string scheme)
    {
        var userInfoRequest = CreateUserInfoRequest();
        var authHeader = new AuthenticationHeaderValue(scheme, null);
        var clientRequest = CreateClientRequest(authHeader: authHeader);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, userInfoRequest, clientRequest);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
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
                TestTenant.Matched, "invalid_token",
                It.IsAny<TokenTypePolicy>(), It.Is<ValidationOptions>(o => (o & ~ValidationOptions.ValidateAudience) != 0)))
            .ReturnsAsync(validationError);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, userInfoRequest, clientRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
        Assert.Equal("Token is expired", error.ErrorDescription);
    }

    /// <summary>
    /// Only an access token opens this endpoint. RFC 9068 Section 4: "The resource server MUST verify that the 'typ'
    /// header value is 'at+jwt' or 'application/at+jwt' and reject tokens carrying any other value." The validator
    /// is asked for exactly that type, and its refusal reaches the caller as an invalid token.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenOfAnotherType_IsRejected()
    {
        var userInfoRequest = CreateUserInfoRequest("id_token_value");
        var clientRequest = CreateClientRequest();

        _jwtValidator
            .Setup(v => v.ValidateAsync(
                TestTenant.Matched, "id_token_value",
                TokenTypesArg.Is(TokenTypePolicy.Exactly(JsonWebTokenTypes.AccessToken)),
                It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidTokenType, "an ID token"));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, userInfoRequest, clientRequest);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
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
                TestTenant.Matched, "valid_token",
                It.IsAny<TokenTypePolicy>(), It.Is<ValidationOptions>(o => (o & ~ValidationOptions.ValidateAudience) != 0)))
            .ReturnsAsync(accessToken);

        _accessTokenService
            .Setup(s => s.AuthenticateByAccessTokenAsync(TestTenant.Matched, accessToken, It.IsAny<ClientInfo>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)new AuthorizedGrant(authSession, authContext));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, "unknown_client"))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, userInfoRequest, clientRequest);

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
            .Setup(v => v.ValidateAsync(TestTenant.Matched, "token_123", It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .Callback(new Action<TenantDefinition, string, TokenTypePolicy, ValidationOptions>((_, _, _, options) => capturedOptions = options))
            .ReturnsAsync(accessToken);

        _accessTokenService
            .Setup(s => s.AuthenticateByAccessTokenAsync(TestTenant.Matched, accessToken, It.IsAny<ClientInfo>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)new AuthorizedGrant(authSession, authContext));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, userInfoRequest, clientRequest);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.Equal(
            ValidationOptions.RequireValidAudience,
            capturedOptions.Value & ValidationOptions.RequireValidAudience);
    }

    /// <summary>
    /// Arranges a token that validates and a client that is found, so each test below varies only where the token
    /// travels and which profile holds the client.
    /// </summary>
    private ClientInfo ArrangeValidTokenOfClient(
        string rawToken,
        ClientSecurityProfile? clientProfile,
        AuthorizationContext? authContext = null)
    {
        var accessToken = CreateValidAccessToken();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId) { SecurityProfile = clientProfile };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, rawToken, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(accessToken);

        _accessTokenService
            .Setup(s => s.AuthenticateByAccessTokenAsync(TestTenant.Matched, accessToken, It.IsAny<ClientInfo>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)new AuthorizedGrant(
                CreateAuthSession(), authContext ?? CreateAuthContext()));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, TestConstants.DefaultClientId))
            .ReturnsAsync(clientInfo);

        return clientInfo;
    }

    /// <summary>
    /// FAPI 2.0 Security Profile section 5.3.4: a resource server "shall not accept access tokens in the query
    /// parameters stated in Section 2.3 of OAuth 2.0 Bearer Token Usage". A deployment held to FAPI 2.0 refuses the
    /// token in the URI query, and refuses it before the token opens the user's session.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenInQuery_UnderFapi2Deployment_IsRefused()
    {
        ArrangeValidTokenOfClient("valid_token_123", clientProfile: null);
        var tenant = new TestIssuer { DefaultSecurityProfile = ClientSecurityProfile.Fapi2 }.ToTenant();

        var result = await _validator.ValidateAsync(
            tenant, CreateUserInfoRequest(inQuery: "valid_token_123"), CreateClientRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        _accessTokenService.Verify(
            s => s.AuthenticateByAccessTokenAsync(It.IsAny<TenantDefinition>(), It.IsAny<JsonWebToken>(), It.IsAny<ClientInfo>()),
            Times.Never);
    }

    /// <summary>
    /// The same refusal for a client that names a FAPI profile for itself under a deployment that names no profile:
    /// the client's own choice tightens what it is held to. FAPI 1.0 Part 1 section 6.2.1 words it as FAPI 2.0 does:
    /// "shall not accept access tokens in the query parameters stated in Section 2.3 of OAuth 2.0 Bearer Token Usage".
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced)]
    public async Task ValidateAsync_TokenInQuery_OfFapiClient_IsRefused(ClientSecurityProfile profile)
    {
        ArrangeValidTokenOfClient("valid_token_123", profile);

        var result = await _validator.ValidateAsync(
            SingleIssuer.Tenant, CreateUserInfoRequest(inQuery: "valid_token_123"), CreateClientRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// The clause forbids the query alone, so a FAPI 2.0 deployment still accepts the token in the form-encoded
    /// body of RFC 6750 section 2.2.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenInForm_UnderFapi2Deployment_IsAccepted()
    {
        var clientInfo = ArrangeValidTokenOfClient("valid_token_123", clientProfile: null);
        var tenant = new TestIssuer { DefaultSecurityProfile = ClientSecurityProfile.Fapi2 }.ToTenant();

        var result = await _validator.ValidateAsync(
            tenant, CreateUserInfoRequest(inForm: "valid_token_123"), CreateClientRequest());

        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(clientInfo, validRequest.ClientInfo);
    }

    /// <summary>
    /// The header stays the way in for a FAPI 2.0 client, so the refusal above is about where the token travels and
    /// not about the client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenInHeader_OfFapi2Client_IsAccepted()
    {
        var clientInfo = ArrangeValidTokenOfClient("valid_token_123", ClientSecurityProfile.Fapi2);
        var clientRequest = CreateClientRequest(
            authHeader: new AuthenticationHeaderValue(TokenTypes.Bearer, "valid_token_123"));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateUserInfoRequest(), clientRequest);

        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(clientInfo, validRequest.ClientInfo);
    }

    /// <summary>
    /// A client under no profile keeps RFC 6750 section 2.3: the token in the URI query is accepted.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenInQuery_OfUnprofiledClient_IsAccepted()
    {
        var clientInfo = ArrangeValidTokenOfClient("valid_token_123", clientProfile: null);

        var result = await _validator.ValidateAsync(
            SingleIssuer.Tenant, CreateUserInfoRequest(inQuery: "valid_token_123"), CreateClientRequest());

        Assert.True(result.TryGetSuccess(out var validRequest));
        Assert.Same(clientInfo, validRequest.ClientInfo);
    }

    /// <summary>
    /// RFC 6750 section 3.1: a request that "uses more than one method for including an access token" is an
    /// invalid_request, so the token in both the query and the body is refused before either is read.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenInQueryAndForm_IsRefused()
    {
        var result = await _validator.ValidateAsync(
            SingleIssuer.Tenant,
            CreateUserInfoRequest(inForm: "token_in_form", inQuery: "token_in_query"),
            CreateClientRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// OpenID Connect Core 1.0 section 5.3: the client calls the UserInfo Endpoint "using an Access Token obtained
    /// through OpenID Connect Authentication", which is a token carrying the openid scope. FAPI 2.0 Security Profile
    /// section 5.3.4 has the resource server "verify that the authorization represented by the access token is
    /// sufficient for the requested resource access and otherwise return errors as in Section 3.1", which names that
    /// insufficient_scope.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenWithoutOpenIdScope_IsInsufficientScope()
    {
        ArrangeValidTokenOfClient(
            "valid_token_123",
            clientProfile: null,
            new AuthorizationContext(TestConstants.DefaultClientId, [Scopes.Profile], requestedClaims: null));
        var clientRequest = CreateClientRequest(
            authHeader: new AuthenticationHeaderValue(TokenTypes.Bearer, "valid_token_123"));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateUserInfoRequest(), clientRequest);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InsufficientScope, error.Error);
    }
}
