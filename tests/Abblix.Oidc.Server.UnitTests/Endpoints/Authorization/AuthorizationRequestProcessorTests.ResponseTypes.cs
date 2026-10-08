// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.ResponseObject;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

public partial class AuthorizationRequestProcessorTests
{
    /// <summary>
    /// Verifies successful authorization with authorization code.
    /// Per OAuth 2.0, response_type=code generates authorization code.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeCode_ShouldGenerateAuthorizationCode()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Code]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var expectedCode = "auth_code_123";

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync(expectedCode);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Equal(expectedCode, success.Code);
        Assert.Null(success.AccessToken);
        Assert.Null(success.IdToken);
    }

    /// <summary>
    /// Verifies successful authorization with access token.
    /// Per OAuth 2.0 Implicit Flow, response_type=token generates access token.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeToken_ShouldGenerateAccessToken()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Token]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var jwt = new JsonWebToken();
        var expectedToken = new EncodedJsonWebToken(jwt, "access_token_jwt");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(session, It.IsAny<AuthorizationContext>(), request.ClientInfo, null, It.IsAny<DateTimeOffset?>()))
            .ReturnsAsync(expectedToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Null(success.Code);
        Assert.Same(expectedToken, success.AccessToken);
        Assert.Equal(TokenTypes.Bearer, success.TokenType);
        Assert.Null(success.IdToken);
    }

    /// <summary>
    /// RFC 6749 section 3.3 / section 4.2.2: when the consent decision narrows the grant, the front-channel
    /// <c>scope</c> parameter of an implicit/hybrid response must advertise the GRANTED scope
    /// (matching the issued access token), not the broader requested set. Drives the real processor and
    /// the real <see cref="AuthorizationResponseEncoder"/> end to end.
    /// </summary>
    [Fact]
    public async Task ProcessAndEncode_ImplicitFlowWithNarrowedConsent_EmitsGrantedScopeNotRequested()
    {
        // Arrange - request asks for openid profile email; the consent provider grants only openid profile.
        var request = CreateRequest(
            responseType: [ResponseTypes.Token],
            scope: [Scopes.OpenId, Scopes.Profile, Scopes.Email]);
        var session = CreateAuthSession();
        var consents = CreateConsents(
            grantedScopes: [new ScopeDefinition(Scopes.OpenId), new ScopeDefinition(Scopes.Profile)]);

        var accessToken = new EncodedJsonWebToken(new JsonWebToken(), "access_token_jwt");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(session, It.IsAny<AuthorizationContext>(), request.ClientInfo, null, It.IsAny<DateTimeOffset?>()))
            .ReturnsAsync(accessToken);

        var response = await _processor.ProcessAsync(request);

        // Encode through the real response encoder. Query (non-JARM) mode means no response JWT is built,
        // so the JWT builder is never invoked; iss advertising is disabled to keep the issuer provider idle.
        var metadata = new Mock<IAuthorizationMetadataProvider>(MockBehavior.Strict);
        metadata.SetupGet(m => m.AuthorizationResponseIssParameterSupported).Returns(false);
        var encoder = new AuthorizationResponseEncoder(
            new Mock<IIssuerProvider>(MockBehavior.Strict).Object,
            metadata.Object,
            new Mock<IResponseJwtBuilder>(MockBehavior.Strict).Object);

        // Act
        await encoder.EncodeAsync(response);

        // Assert - the front-channel scope reflects the granted set, not the requested set.
        var success = Assert.IsType<SuccessfullyAuthenticated>(response);
        Assert.Equal($"{Scopes.OpenId} {Scopes.Profile}", success.Scope);
    }

    /// <summary>
    /// Verifies successful authorization with ID token.
    /// Per OIDC Implicit Flow, response_type=id_token generates ID token.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeIdToken_ShouldGenerateIdToken()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.IdToken]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var jwt = new JsonWebToken();
        var expectedIdToken = new EncodedJsonWebToken(jwt, "id_token_jwt");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                session,
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                true,
                null,
                null))
            .ReturnsAsync(expectedIdToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Null(success.Code);
        Assert.Null(success.AccessToken);
        Assert.Same(expectedIdToken, success.IdToken);
    }

    /// <summary>
    /// Verifies hybrid flow with code and token.
    /// Per OIDC Hybrid Flow, response_type=code token generates both.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeCodeToken_ShouldGenerateBoth()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Code, ResponseTypes.Token]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var expectedCode = "auth_code_123";
        var jwt = new JsonWebToken();
        var expectedToken = new EncodedJsonWebToken(jwt, "access_token_jwt");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync(expectedCode);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(session, It.IsAny<AuthorizationContext>(), request.ClientInfo, null, It.IsAny<DateTimeOffset?>()))
            .ReturnsAsync(expectedToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Equal(expectedCode, success.Code);
        Assert.Same(expectedToken, success.AccessToken);
        Assert.Equal(TokenTypes.Bearer, success.TokenType);
    }

    /// <summary>
    /// Verifies authorization context contains correct data.
    /// Context should include granted scopes, resources, and request parameters.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldBuildCorrectAuthorizationContext()
    {
        // Arrange
        var nonce = "nonce_123";
        var codeChallenge = "challenge_123";
        var codeChallengeMethod = "S256";

        var authRequest = new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            Scope = [Scopes.OpenId, "email"],
            Nonce = nonce,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
        };

        var clientInfo = new ClientInfo(TestConstants.DefaultClientId)
        {
            AuthorizationCodeExpiresIn = TimeSpan.FromMinutes(10),
        };

        var grantedScopes = new[] { new ScopeDefinition(Scopes.OpenId), new ScopeDefinition("email") };
        var grantedResources = new[] { new ResourceDefinition(new Uri("https://api.example.com")) };

        var context = new AuthorizationValidationContext(authRequest)
        {
            ClientInfo = clientInfo,
            ResponseMode = ResponseModes.Query,
            Scope = grantedScopes,
            Resources = grantedResources,
        };

        var request = new ValidAuthorizationRequest(context);
        var session = CreateAuthSession();

        var consents = CreateConsents(grantedScopes: grantedScopes, grantedResources: grantedResources);

        AuthorizedGrant? capturedGrant = null;

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .Callback<AuthorizedGrant, TimeSpan>((grant, _) => capturedGrant = grant)
            .ReturnsAsync("code");

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        Assert.NotNull(capturedGrant);
        var authContext = capturedGrant.Context;
        Assert.Equal(TestConstants.DefaultClientId, authContext.ClientId);
        Assert.Equal(grantedScopes.Select(s => s.Scope).ToArray(), authContext.Scope);
        Assert.Equal(grantedResources.Select(r => r.Resource).ToArray(), authContext.Resources);
        Assert.Equal(nonce, authContext.Nonce);
        Assert.Equal(codeChallenge, authContext.CodeChallenge);
        Assert.Equal(codeChallengeMethod, authContext.CodeChallengeMethod);
        Assert.Equal(request.Model.RedirectUri, authContext.RedirectUri);
    }

    /// <summary>
    /// Verifies hybrid flow with code and id_token.
    /// Per OIDC Hybrid Flow, response_type=code id_token generates both.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeCodeIdToken_ShouldGenerateBoth()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Code, ResponseTypes.IdToken]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var expectedCode = "auth_code_123";
        var jwt = new JsonWebToken();
        var expectedIdToken = new EncodedJsonWebToken(jwt, "id_token_jwt");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync(expectedCode);

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                session,
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                false,
                expectedCode,
                null))
            .ReturnsAsync(expectedIdToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Equal(expectedCode, success.Code);
        Assert.Null(success.AccessToken);
        Assert.Same(expectedIdToken, success.IdToken);
    }

    /// <summary>
    /// Verifies hybrid flow with token and id_token.
    /// Per OIDC Hybrid Flow, response_type=token id_token generates both.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeTokenIdToken_ShouldGenerateBoth()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Token, ResponseTypes.IdToken]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var accessJwt = new JsonWebToken();
        var expectedToken = new EncodedJsonWebToken(accessJwt, "access_token_jwt");
        var idJwt = new JsonWebToken();
        var expectedIdToken = new EncodedJsonWebToken(idJwt, "id_token_jwt");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(session, It.IsAny<AuthorizationContext>(), request.ClientInfo, null, It.IsAny<DateTimeOffset?>()))
            .ReturnsAsync(expectedToken);

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                session,
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                false,
                null,
                expectedToken.EncodedJwt))
            .ReturnsAsync(expectedIdToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Null(success.Code);
        Assert.Same(expectedToken, success.AccessToken);
        Assert.Equal(TokenTypes.Bearer, success.TokenType);
        Assert.Same(expectedIdToken, success.IdToken);
    }

    /// <summary>
    /// Verifies hybrid flow with all three response types.
    /// Per OIDC Hybrid Flow, response_type=code token id_token generates all three.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithResponseTypeCodeTokenIdToken_ShouldGenerateAll()
    {
        // Arrange
        var request = CreateRequest(
            responseType: [ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var expectedCode = "auth_code_123";
        var accessJwt = new JsonWebToken();
        var expectedToken = new EncodedJsonWebToken(accessJwt, "access_token_jwt");
        var idJwt = new JsonWebToken();
        var expectedIdToken = new EncodedJsonWebToken(idJwt, "id_token_jwt");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync(expectedCode);

        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(session, It.IsAny<AuthorizationContext>(), request.ClientInfo, null, It.IsAny<DateTimeOffset?>()))
            .ReturnsAsync(expectedToken);

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                session,
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                false,
                expectedCode,
                expectedToken.EncodedJwt))
            .ReturnsAsync(expectedIdToken);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Equal(expectedCode, success.Code);
        Assert.Same(expectedToken, success.AccessToken);
        Assert.Equal(TokenTypes.Bearer, success.TokenType);
        Assert.Same(expectedIdToken, success.IdToken);
    }

    /// <summary>
    /// Verifies successful authorization with all session data passed to tokens.
    /// Session details should be included in authorization grant.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldPassSessionToTokenServices()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.Code]);
        var session = CreateAuthSession();
        var consents = CreateConsents();

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.Is<AuthorizedGrant>(g => g.AuthSession == session),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        _authorizationCodeService.Verify(
            s => s.GenerateAuthorizationCodeAsync(
                It.Is<AuthorizedGrant>(g => g.AuthSession == session),
                request.ClientInfo.AuthorizationCodeExpiresIn),
            Times.Once);
    }

    /// <summary>
    /// Verifies successful authorization includes session ID in result.
    /// Session ID should be preserved in the authentication result.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldIncludeSessionIdInResult()
    {
        // Arrange
        var sessionId = "test_session_id_123";
        var request = CreateRequest();
        var session = CreateAuthSession(sessionId: sessionId);
        var consents = CreateConsents();

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var success = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Equal(sessionId, success.SessionId);
    }

    /// <summary>
    /// Verifies ID token generation when it's the only response type.
    /// When response_type=id_token only, at_hash and c_hash should not be included.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithIdTokenOnly_ShouldNotIncludeHashClaims()
    {
        // Arrange
        var request = CreateRequest(responseType: [ResponseTypes.IdToken]);
        var session = CreateAuthSession();
        var consents = CreateConsents();
        var jwt = new JsonWebToken();
        var expectedIdToken = new EncodedJsonWebToken(jwt, "id_token_jwt");

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(
                session,
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                true,
                null,
                null))
            .ReturnsAsync(expectedIdToken);

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        _identityTokenService.Verify(
            s => s.CreateIdentityTokenAsync(
                session,
                It.IsAny<AuthorizationContext>(),
                request.ClientInfo,
                true,
                null,
                null),
            Times.Once);
    }
}
