// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
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
        _grantHandler.Setup(h => h.GrantTypesSupported).Returns(SupportedGrantTypes);
        _validator = new AuthorizationGrantValidator(_grantHandler.Object);
    }

    private static readonly string[] SupportedGrantTypes =
    [
        GrantTypes.AuthorizationCode,
        GrantTypes.RefreshToken,
        GrantTypes.ClientCredentials,
        GrantTypes.Password,
        GrantTypes.JwtBearer,
        GrantTypes.Ciba,
        GrantTypes.TokenExchange,
    ];

    /// <summary>
    /// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 3.2.4: unsupported_grant_type is "The authorization grant type is
    /// not supported by the authorization server", so a type no handler serves is answered with it, even for a client
    /// not allowed it, and before the handler is reached. A type differing in case only is another type.
    /// </summary>
    [Theory]
    [InlineData("urn:example:unknown", true)]
    [InlineData("urn:example:unknown", false)]
    [InlineData("Authorization_Code", false)]
    public async Task AGrantTypeNoHandlerServes_IsUnsupportedWhateverTheClientMayUse(string grantType, bool clientMayUseIt)
    {
        var context = CreateContext(
            grantType,
            allowedGrantTypes: clientMayUseIt ? [grantType] : [GrantTypes.AuthorizationCode]);

        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        Assert.Equal(ErrorCodes.UnsupportedGrantType, error?.Error);
        _grantHandler.VerifyGet(h => h.GrantTypesSupported);
        _grantHandler.VerifyNoOtherCalls();
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
        var context = new TokenValidationContext(tokenRequest, clientRequest) { Clients = Mock.Of<IClientInfoProvider>() };

        var clientInfo = new ClientInfo(TestConstants.DefaultClientId)
        {
            AllowedGrantTypes = allowedGrantTypes ?? [grantType],
        };
        context.ClientInfo = clientInfo;

        return context;
    }

    /// <summary>
    /// A grant starting from the client alone builds its context from the request's scope, so a request naming none
    /// reaches its handler with the client's default scope.
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.ClientCredentials)]
    [InlineData(GrantTypes.Password)]
    [InlineData(GrantTypes.JwtBearer)]
    public async Task ARequestNamingNoScope_ReachesItsHandlerWithTheClientsDefault(string grantType)
    {
        var context = new TokenValidationContext(new TokenRequest { GrantType = grantType, Scope = [] }, new ClientRequest())
        {
            Clients = Mock.Of<IClientInfoProvider>(),
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId)
            {
                AllowedGrantTypes = [grantType],
                DefaultScope = ["read"],
            },
        };
        TokenRequest? handed = null;
        _grantHandler
            .Setup(h => h.AuthorizeAsync(TestTenant.Matched, It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), It.IsAny<CancellationToken>()))
            .Callback<TenantDefinition, TokenRequest, ClientInfo, IClientInfoProvider, CancellationToken>((_, request, _, _, _) => handed = request)
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)CreateAuthorizedGrant());

        await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        Assert.Equal("read", Assert.Single(handed?.Scope ?? []));
    }

    private static AuthorizedGrant CreateAuthorizedGrant(Uri? redirectUri = null)
    {
        var authSession = new AuthSession(
            Subject: "user_123",
            SessionId: "session_123",
            AuthenticationTime: TimeProvider.System.GetUtcNow(),
            IdentityProvider: "local");

        var authContext = new AuthorizationContext(
            clientId: TestConstants.DefaultClientId,
            scope: [TestConstants.DefaultScope],
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
            .Setup(h => h.AuthorizeAsync(TestTenant.Matched, It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)(authorizedGrant));

        // Act
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

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
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.UnauthorizedClient, error.Error);
        Assert.Contains("grant type is not allowed", error.ErrorDescription);
        _grantHandler.VerifyGet(h => h.GrantTypesSupported);
        _grantHandler.VerifyNoOtherCalls();
    }

    /// <summary>
    /// RFC 6749 section 4.4.2: for the client credentials grant "The client MUST authenticate", so a client the host's
    /// store serves with the method none and a confidential grant among its own is refused it with
    /// unauthorized_client before the grant's handler is reached.
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.ClientCredentials)]
    [InlineData(GrantTypes.Password)]
    [InlineData(GrantTypes.JwtBearer)]
    [InlineData(GrantTypes.Ciba)]
    public async Task APublicClient_IsRefusedAGrantKeptForConfidentialClients(string grantType)
    {
        var context = CreateContext(grantType);
        context.ClientInfo.TokenEndpointAuthMethod = ClientAuthenticationMethods.None;

        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.UnauthorizedClient, error.Error);
        _grantHandler.VerifyGet(h => h.GrantTypesSupported);
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
            .Setup(h => h.AuthorizeAsync(TestTenant.Matched, It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)(grantError));

        // Act
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert
        Assert.Same(grantError, error);
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
            .Setup(h => h.AuthorizeAsync(TestTenant.Matched, context.Request, context.ClientInfo, It.IsAny<IClientInfoProvider>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)(authorizedGrant));

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert
        _grantHandler.Verify(h => h.AuthorizeAsync(TestTenant.Matched, context.Request, context.ClientInfo, It.IsAny<IClientInfoProvider>(), It.IsAny<CancellationToken>()), Times.Once);
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
        await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert
        _grantHandler.VerifyGet(h => h.GrantTypesSupported);
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
            .Setup(h => h.AuthorizeAsync(TestTenant.Matched, It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)(authorizedGrant));

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

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
            .Setup(h => h.AuthorizeAsync(TestTenant.Matched, It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)(authorizedGrant));

        // Act
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// RFC 6749 section 4.1.3 asks for redirect_uri only on the authorization code grant, and section 3.2 has the
    /// server "ignore unrecognized request parameters", so a grant with no authorization step is not refused for
    /// carrying one: its handler builds a context naming no redirect URI, and the request is served.
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.TokenExchange)]
    [InlineData(GrantTypes.RefreshToken)]
    [InlineData(GrantTypes.ClientCredentials)]
    public async Task ARedirectUriOnAGrantWithoutAnAuthorizationStep_IsIgnored(string grantType)
    {
        var context = CreateContext(grantType, redirectUri: new Uri("https://client.example.com/callback"));
        var authorizedGrant = CreateAuthorizedGrant(redirectUri: null);

        _grantHandler
            .Setup(h => h.AuthorizeAsync(TestTenant.Matched, It.IsAny<TokenRequest>(), It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)authorizedGrant);

        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        Assert.Null(error);
        Assert.Same(authorizedGrant, context.AuthorizedGrant);
    }
}
