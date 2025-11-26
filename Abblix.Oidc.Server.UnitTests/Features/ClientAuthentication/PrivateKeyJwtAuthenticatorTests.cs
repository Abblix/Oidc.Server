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
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="PrivateKeyJwtAuthenticator"/> verifying JWT assertion authentication
/// as defined in RFC 7523 and OpenID Connect Core 1.0.
/// Tests cover JWT validation, replay attack prevention, and various error conditions.
/// </summary>
[Collection("License")]
public class PrivateKeyJwtAuthenticatorTests
{
    private const string ClientId = "test_client_789";
    private const string JwtAssertion = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

    public PrivateKeyJwtAuthenticatorTests(TestInfrastructure.LicenseFixture fixture)
    {
        // Fixture auto-configures license
    }

    /// <summary>
    /// Verifies that valid JWT assertion with matching issuer and subject successfully authenticates the client.
    /// This is the standard flow for private_key_jwt authentication method.
    /// </summary>
    [Fact]
    public async Task ValidJwtAssertion_ShouldAuthenticate()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var validToken = CreateValidJwtToken(ClientId, ClientId);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(validToken, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that authentication fails when client_assertion_type is missing.
    /// Both client_assertion_type and client_assertion are required.
    /// </summary>
    [Fact]
    public async Task MissingClientAssertionType_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when client_assertion is missing.
    /// Both client_assertion_type and client_assertion are required.
    /// </summary>
    [Fact]
    public async Task MissingClientAssertion_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when client_assertion_type is not JWT bearer.
    /// Only urn:ietf:params:oauth:client-assertion-type:jwt-bearer is supported.
    /// </summary>
    [Fact]
    public async Task WrongClientAssertionType_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientAssertionType = "unsupported_type",
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when JWT validation fails.
    /// Invalid JWTs (wrong signature, expired, etc.) should be rejected.
    /// </summary>
    [Fact]
    public async Task InvalidJwt_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid signature"));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when issuer and subject claims don't match.
    /// For client authentication, iss and sub must both equal the client_id.
    /// </summary>
    [Fact]
    public async Task MismatchedIssuerAndSubject_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var invalidToken = CreateValidJwtToken("different_issuer", ClientId);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(invalidToken, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when issuer claim is missing from JWT.
    /// The iss claim is required for client authentication.
    /// </summary>
    [Fact]
    public async Task MissingIssuerClaim_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var tokenWithoutIssuer = CreateValidJwtToken(null, ClientId);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(tokenWithoutIssuer, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when subject claim is missing from JWT.
    /// The sub claim is required for client authentication.
    /// </summary>
    [Fact]
    public async Task MissingSubjectClaim_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var tokenWithoutSubject = CreateValidJwtToken(ClientId, null);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(tokenWithoutSubject, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client is configured to use a different authentication method.
    /// The authenticator only accepts clients configured for private_key_jwt.
    /// </summary>
    [Fact]
    public async Task WrongAuthenticationMethod_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        clientInfo.TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost; // Wrong method

        var validToken = CreateValidJwtToken(ClientId, ClientId);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(validToken, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that the JWT ID (jti) and expiration time (exp) are registered in the token registry.
    /// This prevents replay attacks by ensuring tokens can only be used once.
    /// </summary>
    [Fact]
    public async Task ValidJwtWithJtiAndExp_ShouldRegisterInTokenRegistry()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var jti = "unique_jwt_id_123";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        var validToken = CreateValidJwtTokenWithJtiAndExp(ClientId, ClientId, jti, expiresAt);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(validToken, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        mocks.TokenRegistry.Verify(
            r => r.SetStatusAsync(
                It.Is<string>(id => id == jti),
                It.Is<JsonWebTokenStatus>(s => s == JsonWebTokenStatus.Used),
                It.Is<DateTimeOffset>(exp => Math.Abs((exp - expiresAt).TotalSeconds) < 1)),
            Times.Once);
    }

    /// <summary>
    /// Verifies that authentication succeeds even when jti claim is missing.
    /// While jti is recommended for preventing replay attacks, it's not strictly required.
    /// </summary>
    [Fact]
    public async Task ValidJwtWithoutJti_ShouldAuthenticate()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var validToken = CreateValidJwtToken(ClientId, ClientId);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(validToken, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);
        // Verify no token registry interaction when jti is missing
        mocks.TokenRegistry.Verify(
            r => r.SetStatusAsync(It.IsAny<string>(), It.IsAny<JsonWebTokenStatus>(), It.IsAny<DateTimeOffset>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies that authentication fails when client_assertion is empty string.
    /// </summary>
    [Fact]
    public async Task EmptyClientAssertion_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = string.Empty
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that the authenticator reports the correct supported authentication method.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_ShouldReturnPrivateKeyJwt()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();

        // Act
        var methods = authenticator.ClientAuthenticationMethodsSupported.ToArray();

        // Assert
        Assert.Single(methods);
        Assert.Equal(ClientAuthenticationMethods.PrivateKeyJwt, methods[0]);
    }

    /// <summary>
    /// Creates a new instance of PrivateKeyJwtAuthenticator with mocked dependencies for testing.
    /// </summary>
    /// <returns>A tuple containing the authenticator instance and the mock objects.</returns>
    private (PrivateKeyJwtAuthenticator authenticator, Mocks mocks) CreateAuthenticator()
    {
        var logger = new Mock<ILogger<PrivateKeyJwtAuthenticator>>();
        var tokenRegistry = new Mock<ITokenRegistry>(MockBehavior.Strict);
        var clientJwtValidator = new Mock<IClientJwtValidator>(MockBehavior.Strict);

        // Setup default behavior for token registry
        tokenRegistry
            .Setup(r => r.SetStatusAsync(It.IsAny<string>(), It.IsAny<JsonWebTokenStatus>(), It.IsAny<DateTimeOffset>()))
            .Returns(Task.CompletedTask);

        // Create service provider with scoped services
        var services = new ServiceCollection();
        services.AddScoped<IClientJwtValidator>(_ => clientJwtValidator.Object);
        var serviceProvider = services.BuildServiceProvider();

        var authenticator = new PrivateKeyJwtAuthenticator(
            logger.Object,
            tokenRegistry.Object,
            serviceProvider);

        var mocks = new Mocks
        {
            Logger = logger,
            TokenRegistry = tokenRegistry,
            ClientJwtValidator = clientJwtValidator,
        };

        return (authenticator, mocks);
    }

    /// <summary>
    /// Creates a test ClientInfo object configured for private_key_jwt authentication.
    /// </summary>
    /// <param name="clientId">The client ID.</param>
    /// <returns>A configured ClientInfo object.</returns>
    private ClientInfo CreateClientInfo(string clientId)
    {
        return new ClientInfo(clientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt
        };
    }

    /// <summary>
    /// Creates a valid JWT token with specified issuer and subject.
    /// Uses real JsonObject instances for JWT payload - NOT mocked!
    /// </summary>
    /// <param name="issuer">The issuer claim (iss), or null to omit.</param>
    /// <param name="subject">The subject claim (sub), or null to omit.</param>
    /// <returns>A JsonWebToken with the specified claims.</returns>
    private JsonWebToken CreateValidJwtToken(string? issuer, string? subject)
    {
        var payloadJson = new JsonObject();
        if (issuer != null)
            payloadJson[JwtClaimTypes.Issuer] = issuer;
        if (subject != null)
            payloadJson[JwtClaimTypes.Subject] = subject;

        var headerJson = new JsonObject
        {
            [JwtClaimTypes.Algorithm] = "RS256",
            [JwtClaimTypes.Type] = "JWT"
        };

        return new JsonWebToken
        {
            Header = new JsonWebTokenHeader(headerJson),
            Payload = new JsonWebTokenPayload(payloadJson)
        };
    }

    /// <summary>
    /// Creates a valid JWT token with jti and exp claims for testing token registry.
    /// Uses real JsonObject instances for JWT payload - NOT mocked!
    /// </summary>
    /// <param name="issuer">The issuer claim (iss).</param>
    /// <param name="subject">The subject claim (sub).</param>
    /// <param name="jwtId">The JWT ID claim (jti).</param>
    /// <param name="expiresAt">The expiration time (exp).</param>
    /// <returns>A JsonWebToken with the specified claims.</returns>
    private JsonWebToken CreateValidJwtTokenWithJtiAndExp(
        string issuer,
        string subject,
        string jwtId,
        DateTimeOffset expiresAt)
    {
        var payloadJson = new JsonObject
        {
            [JwtClaimTypes.Issuer] = issuer,
            [JwtClaimTypes.Subject] = subject,
            [JwtClaimTypes.JwtId] = jwtId,
            [JwtClaimTypes.ExpiresAt] = expiresAt.ToUnixTimeSeconds()
        };

        var headerJson = new JsonObject
        {
            [JwtClaimTypes.Algorithm] = "RS256",
            [JwtClaimTypes.Type] = "JWT"
        };

        return new JsonWebToken
        {
            Header = new JsonWebTokenHeader(headerJson),
            Payload = new JsonWebTokenPayload(payloadJson)
        };
    }

    /// <summary>
    /// Container class for holding all mock objects used in tests.
    /// </summary>
    private sealed class Mocks
    {
        public Mock<ILogger<PrivateKeyJwtAuthenticator>> Logger { get; init; } = null!;
        public Mock<ITokenRegistry> TokenRegistry { get; init; } = null!;
        public Mock<IClientJwtValidator> ClientJwtValidator { get; init; } = null!;
    }
}
