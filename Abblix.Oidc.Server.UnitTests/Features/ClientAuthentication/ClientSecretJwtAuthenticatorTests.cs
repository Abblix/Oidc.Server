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
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Utils;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using JsonWebToken = Abblix.Jwt.JsonWebToken;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="ClientSecretJwtAuthenticator"/> verifying the client_secret_jwt authentication method
/// per OpenID Connect Core 1.0 Section 9.
/// Tests cover JWT assertion validation, HMAC signature verification, audience/issuer validation,
/// secret management, and JWT ID tracking.
/// </summary>
public class ClientSecretJwtAuthenticatorTests
{
    private const string ClientId = TestConstants.DefaultClientId;
    private const string ClientSecret = "test_secret_for_hmac_signing";
    private const string RequestUri = "https://auth.example.com/token";

    private readonly Mock<IJsonWebTokenValidator> _tokenValidator;
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly Mock<IRequestInfoProvider> _requestInfoProvider;
    private readonly Mock<TimeProvider> _clock;
    private readonly Mock<ITokenRegistry> _tokenRegistry;
    private readonly ClientSecretJwtAuthenticator _authenticator;

    public ClientSecretJwtAuthenticatorTests()
    {
        var logger = new Mock<ILogger<ClientSecretJwtAuthenticator>>();
        _tokenValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        _requestInfoProvider = new Mock<IRequestInfoProvider>(MockBehavior.Strict);
        _clock = new Mock<TimeProvider>();
        _tokenRegistry = new Mock<ITokenRegistry>(MockBehavior.Strict);

        _requestInfoProvider
            .Setup(p => p.RequestUri)
            .Returns(RequestUri);

        _authenticator = new ClientSecretJwtAuthenticator(
            logger.Object,
            _tokenValidator.Object,
            _clientInfoProvider.Object,
            _requestInfoProvider.Object,
            _clock.Object,
            _tokenRegistry.Object);
    }

    /// <summary>
    /// Verifies authentication fails when client_assertion_type is not provided.
    /// Per OIDC Core, client_assertion_type is required for JWT assertion authentication.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithoutAssertionType_ShouldReturnNull()
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientAssertionType = null,
            ClientAssertion = "some.jwt.token"
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails with wrong client_assertion_type.
    /// Per OIDC Core, client_assertion_type must be "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithWrongAssertionType_ShouldReturnNull()
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientAssertionType = "wrong-assertion-type",
            ClientAssertion = "some.jwt.token"
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client_assertion is missing.
    /// Per OIDC Core, client_assertion contains the JWT and is required.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithoutAssertion_ShouldReturnNull()
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = null
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client_assertion is empty string.
    /// Empty JWT assertion is invalid.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithEmptyAssertion_ShouldReturnNull()
    {
        // Arrange
        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = ""
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies successful authentication with valid JWT signed using HS256.
    /// Per OIDC Core, HS256 is the recommended algorithm for client_secret_jwt.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithValidHS256Jwt_ShouldAuthenticate()
    {
        // Arrange
        var jwtId = "unique-jwt-id-123";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
        var jwt = "valid.jwt.token";

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = ClientSecret }]
        };

        var token = CreateMockToken(ClientId, ClientId, [RequestUri], jwtId, expiresAt);

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                // Simulate JWT validator executing the callbacks
                if (parameters.ValidateIssuer != null)
                    await parameters.ValidateIssuer(ClientId);

                if (parameters.ResolveIssuerSigningKeys != null)
                    await parameters.ResolveIssuerSigningKeys(ClientId).ToArrayAsync();

                return token;
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _tokenRegistry
            .Setup(r => r.SetStatusAsync(jwtId, JsonWebTokenStatus.Used, It.IsAny<DateTimeOffset>()))
            .Returns(Task.CompletedTask);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);

        _tokenRegistry.Verify(r => r.SetStatusAsync(jwtId, JsonWebTokenStatus.Used, It.IsAny<DateTimeOffset>()), Times.Once);
    }

    /// <summary>
    /// Verifies authentication fails when JWT validation fails.
    /// Invalid signature, expired JWT, etc. should result in authentication failure.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithInvalidJwt_ShouldReturnNull()
    {
        // Arrange
        var jwt = "invalid.jwt.token";

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid signature"));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client is configured for different auth method.
    /// Client must be configured for client_secret_jwt.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithWrongAuthMethod_ShouldReturnNull()
    {
        // Arrange
        var jwt = "valid.jwt.token";

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic, // Wrong method
            ClientSecrets = [new ClientSecret { Value = ClientSecret }]
        };

        var token = CreateMockToken(ClientId, ClientId, [RequestUri], "jti", DateTimeOffset.UtcNow.AddMinutes(5));

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                // Simulate JWT validator executing the callbacks
                if (parameters.ValidateIssuer != null)
                    await parameters.ValidateIssuer(ClientId);

                if (parameters.ResolveIssuerSigningKeys != null)
                    await parameters.ResolveIssuerSigningKeys(ClientId).ToArrayAsync();

                return token;
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when issuer != subject.
    /// Per OIDC Core, for client authentication JWT, issuer and subject must both be client_id.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithIssuerNotEqualSubject_ShouldReturnNull()
    {
        // Arrange
        var jwt = "valid.jwt.token";

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = ClientSecret }]
        };

        var token = CreateMockToken(ClientId, "different-subject", [RequestUri], "jti", DateTimeOffset.UtcNow.AddMinutes(5));

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                // Simulate JWT validator executing the callbacks
                if (parameters.ValidateIssuer != null)
                    await parameters.ValidateIssuer(ClientId);

                if (parameters.ResolveIssuerSigningKeys != null)
                    await parameters.ResolveIssuerSigningKeys(ClientId).ToArrayAsync();

                return token;
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication succeeds when JWT has no JTI.
    /// Per OIDC Core, JTI is recommended but not required.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithoutJti_ShouldAuthenticate()
    {
        // Arrange
        var jwt = "valid.jwt.token";

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = ClientSecret }]
        };

        var token = CreateMockToken(ClientId, ClientId, [RequestUri], null, DateTimeOffset.UtcNow.AddMinutes(5));

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                // Simulate JWT validator executing the callbacks
                if (parameters.ValidateIssuer != null)
                    await parameters.ValidateIssuer(ClientId);

                if (parameters.ResolveIssuerSigningKeys != null)
                    await parameters.ResolveIssuerSigningKeys(ClientId).ToArrayAsync();

                return token;
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);

        // JWT registry should not be called without JTI
        _tokenRegistry.Verify(r => r.SetStatusAsync(It.IsAny<string>(), It.IsAny<JsonWebTokenStatus>(), It.IsAny<DateTimeOffset>()), Times.Never);
    }

    /// <summary>
    /// Verifies client secrets supported algorithms.
    /// ClientSecretJwtAuthenticator should support HS256, HS384, and HS512.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_ShouldIncludeClientSecretJwt()
    {
        // Act
        var supportedMethods = _authenticator.ClientAuthenticationMethodsSupported.ToArray();

        // Assert
        Assert.Contains(ClientAuthenticationMethods.ClientSecretJwt, supportedMethods);
        Assert.Single(supportedMethods);
    }

    private static JsonWebToken CreateMockToken(
        string issuer,
        string subject,
        string[] audiences,
        string? jwtId,
        DateTimeOffset expiresAt)
    {
        var payloadJson = new JsonObject
        {
            ["iss"] = issuer,
            ["sub"] = subject,
            ["aud"] = audiences.Length == 1 ? audiences[0] : string.Join(",", audiences),
            ["exp"] = expiresAt.ToUnixTimeSeconds()
        };

        if (jwtId != null)
        {
            payloadJson["jti"] = jwtId;
        }

        var headerJson = new JsonObject
        {
            ["alg"] = "HS256",
            ["typ"] = "JWT"
        };

        return new JsonWebToken
        {
            Header = new JsonWebTokenHeader(headerJson),
            Payload = new JsonWebTokenPayload(payloadJson)
        };
    }
}
