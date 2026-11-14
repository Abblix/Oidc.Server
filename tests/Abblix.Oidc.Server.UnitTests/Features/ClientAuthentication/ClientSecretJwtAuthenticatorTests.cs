// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.DependencyInjection;
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
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using JsonWebToken = Abblix.Jwt.JsonWebToken;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;

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
    private const string IssuerIdentifier = "https://issuer.example.com";
    private const string TokenEndpoint = IssuerIdentifier + "/connect/token";
    private const string AnotherRecipient = "https://another.example.com";

    private static readonly TenantDefinition Tenant = new TestIssuer { Issuer = new Uri(IssuerIdentifier) }.ToTenant();

    private readonly Mock<IJsonWebTokenValidator> _tokenValidator;
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly FakeTimeProvider _clock;
    private readonly Mock<IReplayCache> _replayCache;
    private readonly ClientSecretJwtAuthenticator _authenticator;

    public ClientSecretJwtAuthenticatorTests()
    {
        var logger = new Mock<ILogger<ClientSecretJwtAuthenticator>>();
        _tokenValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        _clock = new FakeTimeProvider();
        _replayCache = new Mock<IReplayCache>(MockBehavior.Strict);

        _authenticator = new ClientSecretJwtAuthenticator(
            logger.Object,
            new ProfiledJwtValidator(_tokenValidator.Object),
            _clientInfoProvider.Object,
            _clock,
            _replayCache.Object,
            new ServiceCollection().BuildServiceProvider());
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
        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, request);

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
        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, request);

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
        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, request);

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
        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// RFC 10070 section 4: the issuer identifier is the sole audience a client authentication assertion may
    /// carry, compared as written (RFC 3986 section 6.2.1), so the token endpoint, the issuer spelled in
    /// another case, with its default port or a trailing slash, and the issuer beside another recipient are
    /// all refused - before the assertion's identifier is reserved, which the strict replay cache would report.
    /// </summary>
    [Theory]
    [InlineData(IssuerIdentifier + "/token")]
    [InlineData("https://ISSUER.example.com")]
    [InlineData("HTTPS://issuer.example.com")]
    [InlineData("https://issuer.example.com:443")]
    [InlineData(IssuerIdentifier + "/")]
    [InlineData(IssuerIdentifier, "https://another.example.com")]
    public async Task TryAuthenticateClientAsync_AnAudienceOtherThanTheIssuerAlone_IsRefused(params string[] audiences)
    {
        const string jwt = "valid.jwt.token";
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = ClientSecret }]
        };

        var token = CreateMockToken(ClientId, ClientId, [IssuerIdentifier], "jti", _clock.GetUtcNow().AddMinutes(5));
        token.Payload.Audiences = audiences;

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                await parameters.ResolveIssuerSigningKeys!(ClientId).ToArrayAsync();
                return await parameters.ValidateIssuer!(ClientId)
                    ? token
                    : new JwtValidationError(JwtError.InvalidToken, "Invalid issuer");
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId))
            .ReturnsAsync(clientInfo);

        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt,
        });

        Assert.Null(result);
    }

    /// <summary>
    /// The exception a host gives a client that still names the token endpoint, as OpenID Connect Core 1.0 section 9
    /// recommends, holds for a client signing with its secret as for one signing with its key: the token endpoint URL
    /// on the issuer's host is accepted for a client allowed it and refused for any other, and the same URL beside
    /// another recipient is accepted only from a client allowed arrays too.
    /// </summary>
    [Theory]
    [InlineData(ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint, new[] { TokenEndpoint }, true)]
    [InlineData(ClientAssertionAudiences.Issuer, new[] { TokenEndpoint }, false)]
    [InlineData(ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint, new[] { AnotherRecipient, TokenEndpoint }, false)]
    [InlineData(ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint | ClientAssertionAudiences.AllowArray, new[] { AnotherRecipient, TokenEndpoint }, true)]
    public async Task TryAuthenticateClientAsync_TokenEndpointAudience_IsAcceptedInTheFormsTheClientIsAllowed(
        ClientAssertionAudiences audiences, string[] audience, bool accepted)
    {
        const string jwt = "valid.jwt.token";
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = ClientSecret }],
            ClientAssertionAudiences = audiences,
        };

        var token = CreateMockToken(ClientId, ClientId, audience, "jti-token-endpoint", _clock.GetUtcNow().AddMinutes(5));
        token.Payload.Json[JwtClaimTypes.Audience] = audience is [var only]
            ? only
            : new JsonArray([.. audience.Select(member => (JsonNode?)member)]);

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                await parameters.ResolveIssuerSigningKeys!(ClientId).ToArrayAsync();
                return await parameters.ValidateIssuer!(ClientId)
                    ? token
                    : new JwtValidationError(JwtError.InvalidToken, "Invalid issuer");
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId))
            .ReturnsAsync(clientInfo);

        _replayCache
            .Setup(r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(true);

        var endpointResolver = new Mock<IOidcEndpointResolver>();
        endpointResolver.Setup(r => r.Resolve(OidcEndpoints.Token)).Returns(new Uri(TokenEndpoint));
        var services = new ServiceCollection();
        services.AddScoped<IOidcEndpointResolver>(_ => endpointResolver.Object);

        var authenticator = new ClientSecretJwtAuthenticator(
            Mock.Of<ILogger<ClientSecretJwtAuthenticator>>(),
            new ProfiledJwtValidator(_tokenValidator.Object),
            _clientInfoProvider.Object,
            _clock,
            _replayCache.Object,
            services.BuildServiceProvider(validateScopes: true));

        var result = await authenticator.TryAuthenticateClientAsync(Tenant, new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt,
        });

        Assert.Equal(accepted, result is not null);
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
        var expiresAt = _clock.GetUtcNow().AddMinutes(5);
        var jwt = "valid.jwt.token";

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = ClientSecret }]
        };

        var token = CreateMockToken(ClientId, ClientId, [IssuerIdentifier], jwtId, expiresAt);

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                // In the order the JWT validator runs them: the signing keys, then the issuer
                if (parameters.ResolveIssuerSigningKeys != null)
                    await parameters.ResolveIssuerSigningKeys(ClientId).ToArrayAsync();

                if (parameters.ValidateIssuer != null)
                {
                    var issuerValid = await parameters.ValidateIssuer(ClientId);
                    if (!issuerValid)
                        return new JwtValidationError(JwtError.InvalidToken, "Invalid issuer");
                }

                return token;
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId))
            .ReturnsAsync(clientInfo);

        _replayCache
            .Setup(r => r.TryReserveAsync(jwtId, It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(true);

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);

        _replayCache.Verify(r => r.TryReserveAsync(jwtId, It.IsAny<DateTimeOffset>()), Times.Once);
    }

    /// <summary>
    /// Verifies authentication is rejected when the assertion's algorithm does not match the
    /// client's registered token_endpoint_auth_signing_alg (OIDC Core section 9 / RFC 7591): the client
    /// registered HS384 but the assertion is signed with HS256.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithMismatchedSigningAlg_ShouldReturnNull()
    {
        // Arrange
        var jwt = "valid.jwt.token";

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            TokenEndpointAuthSigningAlgorithm = SigningAlgorithms.HS384,
            ClientSecrets = [new ClientSecret { Value = ClientSecret }],
        };

        // CreateMockToken signs with HS256, which does not match the registered HS384.
        var token = CreateMockToken(ClientId, ClientId, [IssuerIdentifier], "jti", _clock.GetUtcNow().AddMinutes(5));

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                if (parameters.ValidateIssuer != null)
                    await parameters.ValidateIssuer(ClientId);
                if (parameters.ResolveIssuerSigningKeys != null)
                    await parameters.ResolveIssuerSigningKeys(ClientId).ToArrayAsync();
                return token;
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt,
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, request);

        // Assert
        Assert.Null(result);
        _replayCache.Verify(
            r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies authentication succeeds when the assertion's algorithm matches the client's
    /// registered token_endpoint_auth_signing_alg.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithMatchingSigningAlg_ShouldAuthenticate()
    {
        // Arrange
        var jwtId = "unique-jwt-id-456";
        var jwt = "valid.jwt.token";

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            TokenEndpointAuthSigningAlgorithm = SigningAlgorithms.HS256,
            ClientSecrets = [new ClientSecret { Value = ClientSecret }],
        };

        var token = CreateMockToken(ClientId, ClientId, [IssuerIdentifier], jwtId, _clock.GetUtcNow().AddMinutes(5));

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                if (parameters.ValidateIssuer != null)
                    await parameters.ValidateIssuer(ClientId);
                if (parameters.ResolveIssuerSigningKeys != null)
                    await parameters.ResolveIssuerSigningKeys(ClientId).ToArrayAsync();
                return token;
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId))
            .ReturnsAsync(clientInfo);

        _replayCache
            .Setup(r => r.TryReserveAsync(jwtId, It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(true);

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt,
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);
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
        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, request);

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

        var token = CreateMockToken(ClientId, ClientId, [IssuerIdentifier], "jti", _clock.GetUtcNow().AddMinutes(5));

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                // In the order the JWT validator runs them: the signing keys, then the issuer
                if (parameters.ResolveIssuerSigningKeys != null)
                    await parameters.ResolveIssuerSigningKeys(ClientId).ToArrayAsync();

                if (parameters.ValidateIssuer != null)
                {
                    var issuerValid = await parameters.ValidateIssuer(ClientId);
                    if (!issuerValid)
                        return new JwtValidationError(JwtError.InvalidToken, "Invalid issuer");
                }

                return token;
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, request);

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

        var token = CreateMockToken(ClientId, "different-subject", [IssuerIdentifier], "jti", _clock.GetUtcNow().AddMinutes(5));

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                // In the order the JWT validator runs them: the signing keys, then the issuer
                if (parameters.ResolveIssuerSigningKeys != null)
                    await parameters.ResolveIssuerSigningKeys(ClientId).ToArrayAsync();

                if (parameters.ValidateIssuer != null)
                {
                    var issuerValid = await parameters.ValidateIssuer(ClientId);
                    if (!issuerValid)
                        return new JwtValidationError(JwtError.InvalidToken, "Invalid issuer");
                }

                return token;
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication is rejected when the assertion has no jti. OpenID Connect Core section 9
    /// makes jti REQUIRED ("A unique identifier for the token, which can be used to prevent reuse
    /// of the token"); without it the assertion is replayable within its expiry window.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithoutJti_ShouldReturnNull()
    {
        // Arrange
        var jwt = "valid.jwt.token";

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
            ClientSecrets = [new ClientSecret { Value = ClientSecret }]
        };

        var token = CreateMockToken(ClientId, ClientId, [IssuerIdentifier], null, _clock.GetUtcNow().AddMinutes(5));

        _tokenValidator
            .Setup(v => v.ValidateAsync(jwt, It.IsAny<ValidationParameters>()))
            .Returns(new Func<string, ValidationParameters, Task<Result<JsonWebToken, JwtValidationError>>>(async (_, parameters) =>
            {
                // In the order the JWT validator runs them: the signing keys, then the issuer
                if (parameters.ResolveIssuerSigningKeys != null)
                    await parameters.ResolveIssuerSigningKeys(ClientId).ToArrayAsync();

                if (parameters.ValidateIssuer != null)
                {
                    var issuerValid = await parameters.ValidateIssuer(ClientId);
                    if (!issuerValid)
                        return new JwtValidationError(JwtError.InvalidToken, "Invalid issuer");
                }

                return token;
            }));

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = jwt
        };

        // Act
        var result = await _authenticator.TryAuthenticateClientAsync(Tenant, request);

        // Assert
        Assert.Null(result);

        // A rejected assertion is never recorded in the replay cache.
        _replayCache.Verify(r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()), Times.Never);
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
