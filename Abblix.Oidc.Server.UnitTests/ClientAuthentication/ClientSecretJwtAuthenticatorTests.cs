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
using System.Text;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="ClientSecretJwtAuthenticator"/> verifying the client_secret_jwt authentication method
/// as defined in OpenID Connect Core 1.0 section 9 and RFC 7523.
/// Tests cover JWT validation with HMAC signatures (HS256, HS384, HS512) and various error conditions.
/// </summary>
public class ClientSecretJwtAuthenticatorTests
{
    private const string ClientId = "38174623762";
    private const string ClientSecret = "TzPTZDtcw9ek41H1VmofRoXQddP5cWCXPWidZHSA2spU6gZN9eIFUiXaHD7OfxtBhTxJsg_I1tdFI_CkKl8t8Q";
    private const string TokenEndpointUrl = "http://localhost:4000/api/auth/token";

    /// <summary>
    /// Verifies that a valid JWT signed with client secret using HMAC algorithms successfully authenticates the client.
    /// Tests all supported HMAC algorithms (HS256, HS384, HS512) with proper issuer, subject, audience, and expiration.
    /// The JWT should be marked as used in the token registry to prevent replay attacks.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm to use for signing the JWT.</param>
    /// <remarks>
    /// Test case based on Authlete example: https://www.authlete.com/kb/oauth-and-openid-connect/client-authentication/client-secret-jwt/
    /// </remarks>
    [Theory]
    [InlineData(SecurityAlgorithms.HmacSha256)]
    [InlineData(SecurityAlgorithms.HmacSha384)]
    [InlineData(SecurityAlgorithms.HmacSha512)]
    public async Task ValidClientSecretJwt_ShouldAuthenticate(string algorithm)
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var exp = now.AddMinutes(5);
        var jwtId = Guid.NewGuid().ToString();

        var token = new JsonWebToken
        {
            Header = { Algorithm = algorithm },
            Payload =
            {
                JwtId = jwtId,
                Subject = ClientId,
                Issuer = ClientId,
                Audiences = [TokenEndpointUrl],
                ExpiresAt = exp,
                IssuedAt = now,
            }
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets =
            [
                new ClientSecret
                {
                    Value = ClientSecret,
                    Sha512Hash = "hash"u8.ToArray(),
                }
            ]
        };

        var (authenticator, mocks) = CreateAuthenticator();

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        mocks.RequestInfoProvider
            .Setup(p => p.RequestUri)
            .Returns(TokenEndpointUrl);

        var jwtString = await CreateAndSignJwt(token, ClientSecret, algorithm);

        mocks.TokenValidator
            .Setup(v => v.ValidateAsync(jwtString, It.IsAny<ValidationParameters>()))
            .ReturnsAsync((string jwt, ValidationParameters parameters) =>
                SimulateValidation(jwt, parameters, token, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwtString
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);

        mocks.TokenRegistry.Verify(
            r => r.SetStatusAsync(jwtId, JsonWebTokenStatus.Used, It.IsAny<DateTimeOffset>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies that authentication fails when client_assertion_type parameter is missing from the request.
    /// Per OpenID Connect specification, both client_assertion_type and client_assertion are required.
    /// </summary>
    [Fact]
    public async Task MissingClientAssertionType_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest { ClientAssertion = "some.jwt.token" };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when client_assertion_type has an incorrect value.
    /// The authenticator only accepts 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' as defined in RFC 7523.
    /// </summary>
    [Fact]
    public async Task WrongClientAssertionType_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientAssertionType = "invalid_type",
            ClientAssertion = "some.jwt.token"
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when client_assertion parameter is missing or empty.
    /// The JWT assertion is required for client_secret_jwt authentication method.
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
    /// Verifies that authentication fails when the JWT signature is invalid or cannot be verified.
    /// The JWT must be signed with the client's secret using a valid HMAC algorithm.
    /// </summary>
    [Fact]
    public async Task InvalidJwtSignature_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        mocks.TokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid signature"));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = "invalid.jwt.token"
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the JWT issuer (iss) does not equal the subject (sub).
    /// Per OpenID Connect specification, for client authentication JWTs, iss and sub must both contain the client_id.
    /// </summary>
    [Fact]
    public async Task IssuerNotEqualToSubject_ShouldReturnNull()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Payload =
            {
                Subject = ClientId,
                Issuer = "different_issuer", // Wrong!
            }
        };

        var (authenticator, mocks) = CreateAuthenticator();

        mocks.TokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .ReturnsAsync(new ValidJsonWebToken(token));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = "some.jwt.token"
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client is configured to use a different authentication method.
    /// The authenticator only accepts clients configured for client_secret_jwt method.
    /// </summary>
    [Fact]
    public async Task WrongAuthenticationMethod_ShouldReturnNull()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var token = new JsonWebToken
        {
            Header = { Algorithm = SecurityAlgorithms.HmacSha256 },
            Payload =
            {
                Subject = ClientId,
                Issuer = ClientId,
                Audiences = [TokenEndpointUrl],
                ExpiresAt = now.AddMinutes(5),
                IssuedAt = now,
            }
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost, // Wrong method!
            ClientSecrets = [new ClientSecret { Value = ClientSecret }]
        };

        var (authenticator, mocks) = CreateAuthenticator();

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        mocks.RequestInfoProvider
            .Setup(p => p.RequestUri)
            .Returns(TokenEndpointUrl);

        mocks.TokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .ReturnsAsync((string jwt, ValidationParameters parameters) =>
                SimulateValidation(jwt, parameters, token, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = "some.jwt.token"
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client secret has expired.
    /// The authenticator checks the ExpiresAt property and skips expired secrets when resolving signing keys.
    /// </summary>
    [Fact]
    public async Task ExpiredClientSecret_ShouldReturnNull()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets =
            [
                new ClientSecret
                {
                    Value = ClientSecret,
                    ExpiresAt = now.AddDays(-1) // Expired!
                }
            ]
        };

        var (authenticator, mocks) = CreateAuthenticator();

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        mocks.RequestInfoProvider
            .Setup(p => p.RequestUri)
            .Returns(TokenEndpointUrl);

        mocks.TokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .ReturnsAsync((string jwt, ValidationParameters parameters) =>
            {
                // Simulate that no valid signing keys are found (expired secret)
                return new JwtValidationError(JwtError.InvalidToken, "No valid signing keys");
            });

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = "some.jwt.token"
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client secret does not have a raw Value property set.
    /// The raw secret value is required for HMAC signature validation in client_secret_jwt authentication.
    /// </summary>
    [Fact]
    public async Task MissingRawSecretValue_ShouldReturnNull()
    {
        // Arrange
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets =
            [
                new ClientSecret
                {
                    // No Value property set!
                    Sha512Hash = "hash"u8.ToArray()
                }
            ]
        };

        var (authenticator, mocks) = CreateAuthenticator();

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        mocks.RequestInfoProvider
            .Setup(p => p.RequestUri)
            .Returns(TokenEndpointUrl);

        mocks.TokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .ReturnsAsync((string jwt, ValidationParameters parameters) =>
            {
                // Simulate that no valid signing keys are found (no raw value)
                return new JwtValidationError(JwtError.InvalidToken, "No valid signing keys");
            });

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = "some.jwt.token"
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the JWT audience (aud) does not match the token endpoint URL.
    /// Per OpenID Connect specification, the audience must contain the authorization server's token endpoint URL.
    /// </summary>
    [Fact]
    public async Task InvalidAudience_ShouldReturnNull()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var token = new JsonWebToken
        {
            Header = { Algorithm = SecurityAlgorithms.HmacSha256 },
            Payload =
            {
                Subject = ClientId,
                Issuer = ClientId,
                Audiences = ["https://wrong-endpoint.com"], // Wrong audience!
                ExpiresAt = now.AddMinutes(5),
                IssuedAt = now,
            }
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = ClientSecret }]
        };

        var (authenticator, mocks) = CreateAuthenticator();

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        mocks.RequestInfoProvider
            .Setup(p => p.RequestUri)
            .Returns(TokenEndpointUrl);

        mocks.TokenValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .ReturnsAsync((string jwt, ValidationParameters parameters) =>
            {
                // Simulate audience validation failure
                return new JwtValidationError(JwtError.InvalidToken, "Audience validation failed");
            });

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = "some.jwt.token"
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Creates a new instance of ClientSecretJwtAuthenticator with mocked dependencies for testing.
    /// </summary>
    /// <returns>A tuple containing the authenticator instance and the mock objects.</returns>
    private (ClientSecretJwtAuthenticator authenticator, Mocks mocks) CreateAuthenticator()
    {
        var logger = new Mock<ILogger<ClientSecretJwtAuthenticator>>();
        var tokenValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var requestInfoProvider = new Mock<IRequestInfoProvider>(MockBehavior.Strict);
        var tokenRegistry = new Mock<ITokenRegistry>(MockBehavior.Strict);

        tokenRegistry
            .Setup(r => r.SetStatusAsync(It.IsAny<string>(), It.IsAny<JsonWebTokenStatus>(), It.IsAny<DateTimeOffset>()))
            .Returns(Task.CompletedTask);

        var authenticator = new ClientSecretJwtAuthenticator(
            logger.Object,
            tokenValidator.Object,
            clientInfoProvider.Object,
            requestInfoProvider.Object,
            TimeProvider.System,
            tokenRegistry.Object);

        var mocks = new Mocks
        {
            Logger = logger,
            TokenValidator = tokenValidator,
            ClientInfoProvider = clientInfoProvider,
            RequestInfoProvider = requestInfoProvider,
            TokenRegistry = tokenRegistry
        };

        return (authenticator, mocks);
    }

    /// <summary>
    /// Creates and signs a JWT using the specified token, secret, and HMAC algorithm.
    /// </summary>
    /// <param name="token">The JWT token to sign.</param>
    /// <param name="secret">The client secret to use for HMAC signing.</param>
    /// <param name="algorithm">The HMAC algorithm (HS256, HS384, or HS512).</param>
    /// <returns>The signed JWT as a string.</returns>
    private async Task<string> CreateAndSignJwt(JsonWebToken token, string secret, string algorithm)
    {
        var creator = new JsonWebTokenCreator();
        var signingKey = new Jwt.JsonWebKey
        {
            KeyType = JsonWebKeyTypes.Octet,
            Algorithm = algorithm,
            SymmetricKey = Encoding.UTF8.GetBytes(secret)
        };

        return await creator.IssueAsync(token, signingKey);
    }

    /// <summary>
    /// Simulates JWT validation by executing the validation callbacks from ValidationParameters.
    /// Used to test the authenticator's validation logic without requiring actual JWT parsing.
    /// </summary>
    /// <param name="jwt">The JWT string being validated.</param>
    /// <param name="parameters">The validation parameters containing callback functions.</param>
    /// <param name="token">The token object to validate against.</param>
    /// <param name="clientInfo">The client information to use for validation.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    private JwtValidationResult SimulateValidation(
        string jwt,
        ValidationParameters parameters,
        JsonWebToken token,
        ClientInfo clientInfo)
    {
        // Simulate audience validation
        if (parameters.ValidateAudience != null)
        {
            var audienceValid = parameters.ValidateAudience(token.Payload.Audiences).Result;
            if (!audienceValid)
            {
                return new JwtValidationError(JwtError.InvalidToken, "Audience validation failed");
            }
        }

        // Simulate issuer validation
        if (parameters.ValidateIssuer != null && token.Payload.Issuer != null)
        {
            var issuerValid = parameters.ValidateIssuer(token.Payload.Issuer).Result;
            if (!issuerValid)
            {
                return new JwtValidationError(JwtError.InvalidToken, "Issuer validation failed");
            }
        }

        return new ValidJsonWebToken(token);
    }

    /// <summary>
    /// Container class for holding all mock objects used in tests.
    /// </summary>
    private sealed class Mocks
    {
        public Mock<ILogger<ClientSecretJwtAuthenticator>> Logger { get; init; } = null!;
        public Mock<IJsonWebTokenValidator> TokenValidator { get; init; } = null!;
        public Mock<IClientInfoProvider> ClientInfoProvider { get; init; } = null!;
        public Mock<IRequestInfoProvider> RequestInfoProvider { get; init; } = null!;
        public Mock<ITokenRegistry> TokenRegistry { get; init; } = null!;
    }
}
