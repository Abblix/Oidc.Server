// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Common.Configuration;
using System.Globalization;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="PrivateKeyJwtAuthenticator"/> verifying JWT assertion authentication
/// as defined in RFC 7523 and OpenID Connect Core 1.0.
/// Tests cover JWT validation, replay attack prevention, and various error conditions.
/// </summary>
public class PrivateKeyJwtAuthenticatorTests
{
    private const string ClientId = "test_client_789";
    private const string JwtAssertion = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

    public PrivateKeyJwtAuthenticatorTests()
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
        // A spec-valid client assertion carries a jti (OIDC Core section 9 REQUIRED).
        var validToken = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "valid-jti-assertion",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));

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
    /// A JWT made for some other purpose is not proof of who the client is. RFC 8725 Section 3.11 calls this
    /// token confusion, and the sharpest case is an access token the client legitimately holds, presented as
    /// its credential. The last two cases are the reason the refusal is not limited to what this server
    /// issues: the client signs its own assertion, so a credential or a security event it signed elsewhere is
    /// equally within reach. Everything else about the assertion below is valid - issuer, subject, jti and
    /// expiry all check out - so the type is the only thing standing between the two meanings.
    /// </summary>
    [Theory]
    [InlineData(JsonWebTokenTypes.AccessToken)]
    [InlineData(JsonWebTokenTypes.LogoutToken)]
    [InlineData(JwtTypes.RefreshToken)]
    [InlineData(JsonWebTokenTypes.VerifiableCredential)]
    [InlineData(JsonWebTokenTypes.SecurityEvent)]
    public async Task AnotherKindPresentedAsAssertion_ShouldReturnNull(string tokenType)
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "valid-jti-assertion",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        token.Header.Type = tokenType;

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

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
    /// The values a conformant sender may use cannot be enumerated - RFC 7523bis asks for
    /// <c>client-authentication+jwt</c> "or another more specific explicit type value defined by a
    /// specification profiling this specification", and plenty of clients predate the guidance entirely. So an
    /// absent, generic or unfamiliar type has to pass, or the check would refuse honest callers rather than
    /// confused tokens.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(JsonWebTokenTypes.Jwt)]
    [InlineData(JsonWebTokenTypes.ClientAuthentication)]
    [InlineData("something-a-profile-defined+jwt")]
    public async Task APermittedOrUnfamiliarType_ShouldAuthenticate(string? tokenType)
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, $"valid-jti-{tokenType ?? "none"}",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        token.Header.Type = tokenType;

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

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
    /// Verifies that the JWT ID (jti) and expiration time (exp) are recorded in the replay cache.
    /// This prevents replay attacks by ensuring tokens can only be used once.
    /// </summary>
    [Fact]
    public async Task ValidJwtWithJtiAndExp_ShouldRecordInReplayCache()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var jti = "unique_jwt_id_123";
        var expiresAt = DateTimeOffset.Parse(
            "2027-01-01T00:05:00Z", System.Globalization.CultureInfo.InvariantCulture);

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
        mocks.ReplayCache.Verify(
            r => r.TryReserveAsync(
                It.Is<string>(id => id == jti),
                It.Is<DateTimeOffset>(exp =>
                    Math.Abs((exp - expiresAt).TotalSeconds) < 1)),
            Times.Once);
    }

    /// <summary>
    /// Verifies that a replayed assertion is rejected: the replay cache reports the jti as
    /// already present, and the single TryReserveAsync call makes the reserve-and-check atomic -
    /// two concurrent presenters of the same assertion cannot both pass.
    /// </summary>
    [Fact]
    public async Task ReplayedAssertion_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var validToken = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "replayed-jti",
            DateTimeOffset.Parse("2027-01-01T00:05:00Z", System.Globalization.CultureInfo.InvariantCulture));

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(validToken, clientInfo));

        mocks.ReplayCache
            .Setup(r => r.TryReserveAsync("replayed-jti", It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(false);

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
    /// Verifies that an assertion without a jti claim is rejected. OpenID Connect Core section 9 makes
    /// jti REQUIRED ("A unique identifier for the token, which can be used to prevent reuse of the
    /// token"); accepting a jti-less assertion would leave it replayable within its expiry window,
    /// since single-use enforcement keys off jti.
    /// </summary>
    [Fact]
    public async Task AssertionWithoutJti_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var tokenWithoutJti = CreateValidJwtToken(ClientId, ClientId);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(tokenWithoutJti, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
        // A rejected assertion is never recorded in the replay cache.
        mocks.ReplayCache.Verify(
            r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies that an assertion without an exp claim is rejected. RFC 7523 section 3 makes exp REQUIRED
    /// ("The JWT MUST contain an 'exp' (expiration time) claim that limits the time window during
    /// which the JWT can be used"); without it the replay-registry entry has no TTL to key off,
    /// so the assertion would be replayable indefinitely.
    /// </summary>
    [Fact]
    public async Task AssertionWithoutExp_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var tokenWithoutExp = CreateValidJwtTokenWithJti(ClientId, ClientId, "jti-without-exp");

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(tokenWithoutExp, clientInfo));

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
    /// FAPI 2.0 section 5.3.2.1: a server held to the profile "shall only accept its issuer
    /// identifier value (as defined in [RFC8414]) as a string in the aud claim received in client
    /// authentication assertions". An assertion naming the token endpoint satisfies the wider
    /// reading OpenID Connect Core permits and is refused here.
    /// </summary>
    [Theory]
    [InlineData("https://issuer.example.com/connect/token")]
    [InlineData("https://another-issuer.example.com")]
    public async Task Fapi2AssertionAudienceIsNotTheIssuer_ShouldReturnNull(string audience)
    {
        var (authenticator, mocks) = CreateAuthenticator(ClientSecurityProfile.Fapi2);
        var clientInfo = CreateClientInfo(ClientId);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "audience-not-the-issuer",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        token.Payload.Audiences = [audience];

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.Null(result);
    }

    /// <summary>
    /// The issuer alone is accepted, which is what keeps the refusal above from being a check that
    /// refuses every assertion.
    /// </summary>
    [Fact]
    public async Task Fapi2AssertionAudienceIsTheIssuer_ShouldAuthenticate()
    {
        var (authenticator, mocks) = CreateAuthenticator(ClientSecurityProfile.Fapi2);
        var clientInfo = CreateClientInfo(ClientId);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "audience-is-the-issuer",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        token.Payload.Audiences = ["https://issuer.example.com"];

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.NotNull(result);
    }

    /// <summary>
    /// The issuer named alongside another audience is refused: the specification asks for the value
    /// as a string, so an assertion minted for a different recipient cannot be replayed here by
    /// naming both.
    /// </summary>
    [Fact]
    public async Task Fapi2AssertionAudienceCarriesTheIssuerAmongOthers_ShouldReturnNull()
    {
        var (authenticator, mocks) = CreateAuthenticator(ClientSecurityProfile.Fapi2);
        var clientInfo = CreateClientInfo(ClientId);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "audience-among-others",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        token.Payload.Audiences = ["https://issuer.example.com", "https://another.example.com"];

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.Null(result);
    }

    /// <summary>
    /// Without the profile the wider reading stands, so an assertion naming the token endpoint keeps
    /// working. This is what makes the three cases above statements about the profile rather than
    /// about the authenticator.
    /// </summary>
    [Fact]
    public async Task NoProfileAssertionAudienceIsTheTokenEndpoint_ShouldAuthenticate()
    {
        var (authenticator, mocks) = CreateAuthenticator();
        var clientInfo = CreateClientInfo(ClientId);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "audience-outside-the-profile",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        token.Payload.Audiences = ["https://issuer.example.com/connect/token"];

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(JwtAssertion, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.NotNull(result);
    }

    /// <summary>
    /// Creates a new instance of PrivateKeyJwtAuthenticator with mocked dependencies for testing.
    /// </summary>
    /// <returns>A tuple containing the authenticator instance and the mock objects.</returns>
    private (PrivateKeyJwtAuthenticator authenticator, Mocks mocks) CreateAuthenticator(
        ClientSecurityProfile profile = ClientSecurityProfile.None)
    {
        var logger = new Mock<ILogger<PrivateKeyJwtAuthenticator>>();
        var replayCache = new Mock<IReplayCache>(MockBehavior.Strict);
        var clientJwtValidator = new Mock<IClientJwtValidator>(MockBehavior.Strict);

        // Setup default behavior for the replay cache: every jti is fresh
        replayCache
            .Setup(r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(true);

        // Create service provider with scoped services
        var services = new ServiceCollection();
        services.AddScoped<IClientJwtValidator>(_ => clientJwtValidator.Object);
        var serviceProvider = services.BuildServiceProvider();

        var authenticator = new PrivateKeyJwtAuthenticator(
            logger.Object,
            replayCache.Object,
            serviceProvider,
            Mock.Of<IIssuerProvider>(p => p.GetIssuer() == "https://issuer.example.com"),
            Options.Create(new OidcOptions { DefaultSecurityProfile = profile }),
            TimeProvider.System);

        var mocks = new Mocks
        {
            Logger = logger,
            ReplayCache = replayCache,
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
    /// Creates a JWT token with a jti claim but no exp claim, for testing the RFC 7523 section 3
    /// expiration requirement. Uses real JsonObject instances for JWT payload - NOT mocked!
    /// </summary>
    /// <param name="issuer">The issuer claim (iss).</param>
    /// <param name="subject">The subject claim (sub).</param>
    /// <param name="jwtId">The JWT ID claim (jti).</param>
    /// <returns>A JsonWebToken with the specified claims and no expiration.</returns>
    private JsonWebToken CreateValidJwtTokenWithJti(string issuer, string subject, string jwtId)
    {
        var payloadJson = new JsonObject
        {
            [JwtClaimTypes.Issuer] = issuer,
            [JwtClaimTypes.Subject] = subject,
            [JwtClaimTypes.JwtId] = jwtId
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
        public Mock<IReplayCache> ReplayCache { get; init; } = null!;
        public Mock<IClientJwtValidator> ClientJwtValidator { get; init; } = null!;
    }
}
