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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Moq;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="JwtBearerGrantHandler"/> verifying the JWT Bearer grant type
/// as defined in RFC 7523 section 2.1.
/// Tests cover token exchange scenarios where a client exchanges a JWT assertion from a trusted
/// identity provider for an access token at this authorization server.
/// </summary>
public class JwtBearerGrantHandlerTests
{
	private const string ClientId = "trusted_client_123";
	private const string Subject = "user@example.com";
	private const string Issuer = "https://trusted-idp.example.com";
	private const string Assertion = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";

	/// <summary>
	/// Verifies that a valid JWT Bearer request successfully returns an authorized grant.
	/// This is the standard RFC 7523 JWT Bearer flow.
	/// </summary>
	[Fact]
	public async Task ValidRequest_WithValidJwt_ShouldReturnGrant()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt = CreateValidJwt();
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion,
			Scope = ["api.read", "api.write"]
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.NotNull(grant);
		Assert.Equal(Subject, grant.AuthSession.Subject);
		Assert.Equal(Issuer, grant.AuthSession.IdentityProvider);
		Assert.Equal(ClientId, grant.Context.ClientId);
		Assert.Equal(tokenRequest.Scope, grant.Context.Scope);
		Assert.Contains(ClientId, grant.AuthSession.AffectedClientIds);
	}

	/// <summary>
	/// Verifies that a request without the assertion parameter returns an invalid_grant error per RFC 7523.
	/// </summary>
	[Fact]
	public async Task Request_WithoutAssertion_ShouldReturnInvalidGrant()
	{
		// Arrange
		var (handler, _) = CreateHandler();
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = null,
			Scope = ["api.read"]
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		Assert.Contains("assertion", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Verifies that a request with an empty assertion parameter returns an invalid_grant error.
	/// </summary>
	[Fact]
	public async Task Request_WithEmptyAssertion_ShouldReturnInvalidGrant()
	{
		// Arrange
		var (handler, _) = CreateHandler();
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = "",
			Scope = ["api.read"]
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		Assert.Contains("assertion", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Verifies that a request with whitespace-only assertion returns an invalid_grant error.
	/// </summary>
	[Fact]
	public async Task Request_WithWhitespaceAssertion_ShouldReturnInvalidGrant()
	{
		// Arrange
		var (handler, _) = CreateHandler();
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = "   ",
			Scope = ["api.read"]
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
	}

	/// <summary>
	/// Verifies that a JWT assertion that fails validation returns an invalid_grant error.
	/// This covers expired JWTs, invalid signatures, wrong audience, etc.
	/// </summary>
	[Fact]
	public async Task Request_WithInvalidJwt_ShouldReturnInvalidGrant()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		SetupInvalidJwtValidation(mocks.JwtValidator);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion,
			Scope = ["api.read"]
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		Assert.Contains("invalid", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Verifies that a JWT without a 'sub' claim returns an invalid_grant error per RFC 7523 section 3.
	/// </summary>
	[Fact]
	public async Task Request_WithJwtMissingSubject_ShouldReturnInvalidGrant()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt = CreateValidJwt();
		jwt.Payload.Subject = null;
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion,
			Scope = ["api.read"]
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		Assert.Contains("sub", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Verifies that a JWT with an empty 'sub' claim returns an invalid_grant error.
	/// </summary>
	[Fact]
	public async Task Request_WithJwtEmptySubject_ShouldReturnInvalidGrant()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt = CreateValidJwt();
		jwt.Payload.Subject = "";
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion,
			Scope = ["api.read"]
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
	}

	/// <summary>
	/// Verifies that the issuer from the JWT is recorded in the AuthSession for audit trails.
	/// </summary>
	[Fact]
	public async Task ValidRequest_ShouldRecordIssuerInAuthSession()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt = CreateValidJwt();
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Equal(Issuer, grant.AuthSession.IdentityProvider);
	}

	/// <summary>
	/// Verifies that when JWT has no issuer claim, "unknown" is used as the identity provider.
	/// </summary>
	[Fact]
	public async Task ValidRequest_WithNoIssuer_ShouldUseUnknownAsIdentityProvider()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt = CreateValidJwt();
		jwt.Payload.Issuer = null;
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Equal("unknown", grant.AuthSession.IdentityProvider);
	}

	/// <summary>
	/// Verifies that the requested scope is correctly passed to the authorization context.
	/// </summary>
	[Fact]
	public async Task ValidRequest_WithScope_ShouldIncludeScopeInContext()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt = CreateValidJwt();
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var requestedScopes = new[] { TestConstants.DefaultScope, "profile", "email" };
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion,
			Scope = requestedScopes
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Equal(requestedScopes, grant.Context.Scope);
	}

	/// <summary>
	/// Verifies that a request without scope still succeeds with null scope in context.
	/// </summary>
	[Fact]
	public async Task ValidRequest_WithoutScope_ShouldReturnGrantWithNullScope()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt = CreateValidJwt();
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion,
			Scope = null!
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Null(grant.Context.Scope);
	}

	/// <summary>
	/// Verifies that a unique session ID is generated for each JWT Bearer grant request.
	/// </summary>
	[Fact]
	public async Task MultipleRequests_ShouldGenerateUniqueSessionIds()
	{
		// Arrange
		var callCount = 0;
		var (handler, mocks) = CreateHandler(() => $"session_{++callCount}");
		var jwt = CreateValidJwt();
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result1 = await handler.AuthorizeAsync(tokenRequest, clientInfo);
		var result2 = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result1.TryGetSuccess(out var grant1));
		Assert.True(result2.TryGetSuccess(out var grant2));
		Assert.Equal("session_1", grant1.AuthSession.SessionId);
		Assert.Equal("session_2", grant2.AuthSession.SessionId);
		Assert.NotEqual(grant1.AuthSession.SessionId, grant2.AuthSession.SessionId);
	}

	/// <summary>
	/// Verifies that the authentication time is correctly set using the time provider.
	/// </summary>
	[Fact]
	public async Task AuthSession_ShouldUseProvidedAuthenticationTime()
	{
		// Arrange
		var fixedTime = new DateTimeOffset(2024, 11, 20, 15, 30, 0, TimeSpan.Zero);
		var (handler, mocks) = CreateHandler(fixedTime: fixedTime);
		var jwt = CreateValidJwt();
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Equal(fixedTime, grant.AuthSession.AuthenticationTime);
	}

	/// <summary>
	/// Verifies that the handler validates JWT with correct validation options per RFC 7523.
	/// Must validate lifetime, issuer, and audience.
	/// </summary>
	[Fact]
	public async Task JwtValidation_ShouldUseCorrectValidationOptions()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt = CreateValidJwt();
		ValidationParameters? capturedParams = null;
		mocks.JwtValidator
			.Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
			.Callback(new Action<string, ValidationParameters>((_, p) => capturedParams = p))
			.ReturnsAsync(Result<JsonWebToken, JwtValidationError>.Success(jwt));
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.NotNull(capturedParams);
		Assert.True(capturedParams.Options.HasFlag(ValidationOptions.ValidateLifetime));
		Assert.True(capturedParams.Options.HasFlag(ValidationOptions.ValidateIssuer));
		Assert.True(capturedParams.Options.HasFlag(ValidationOptions.ValidateAudience));
	}

	/// <summary>
	/// Verifies that the handler reports the correct supported grant type.
	/// </summary>
	[Fact]
	public void GrantTypesSupported_ShouldReturnJwtBearer()
	{
		// Arrange
		var (handler, _) = CreateHandler();

		// Act
		var grantTypes = handler.GrantTypesSupported.ToArray();

		// Assert
		Assert.Single(grantTypes);
		Assert.Equal(GrantTypes.JwtBearer, grantTypes[0]);
	}

	/// <summary>
	/// Verifies that different subjects in JWT assertions result in different auth sessions.
	/// </summary>
	[Fact]
	public async Task DifferentSubjects_ShouldReturnDistinctAuthSessions()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt1 = CreateValidJwt();
		jwt1.Payload.Subject = "user1@example.com";
		var jwt2 = CreateValidJwt();
		jwt2.Payload.Subject = "user2@example.com";

		mocks.JwtValidator
			.SetupSequence(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
			.ReturnsAsync(Result<JsonWebToken, JwtValidationError>.Success(jwt1))
			.ReturnsAsync(Result<JsonWebToken, JwtValidationError>.Success(jwt2));

		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result1 = await handler.AuthorizeAsync(tokenRequest, clientInfo);
		var result2 = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result1.TryGetSuccess(out var grant1));
		Assert.True(result2.TryGetSuccess(out var grant2));
		Assert.Equal("user1@example.com", grant1.AuthSession.Subject);
		Assert.Equal("user2@example.com", grant2.AuthSession.Subject);
	}

	/// <summary>
	/// Verifies that the affected client IDs collection contains the requesting client.
	/// </summary>
	[Fact]
	public async Task AuthSession_ShouldTrackClientInAffectedClientIds()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt = CreateValidJwt();
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Contains(ClientId, grant.AuthSession.AffectedClientIds);
		Assert.Single(grant.AuthSession.AffectedClientIds);
	}

	/// <summary>
	/// Verifies that with StrictAudienceValidation=false, the application base URI is accepted as valid audience.
	/// Per RFC 7523 Section 3, this is a relaxation of the "SHOULD be token endpoint" recommendation.
	/// </summary>
	[Fact]
	public async Task PermissiveAudienceValidation_WithApplicationUri_ShouldSucceed()
	{
		// Arrange
		var (handler, mocks) = CreateHandler(strictAudienceValidation: false);
		var jwt = CreateValidJwt();
		jwt.Payload.Audiences = ["https://authorization-server.example.com"];
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Equal(Subject, grant.AuthSession.Subject);
	}

	/// <summary>
	/// Verifies that with StrictAudienceValidation=true (default), only the token endpoint URL is accepted.
	/// Application base URI should be rejected per RFC 7523 Section 3 strict interpretation.
	/// </summary>
	[Fact]
	public async Task StrictAudienceValidation_WithApplicationUri_ShouldFail()
	{
		// Arrange
		var (handler, mocks) = CreateHandler(strictAudienceValidation: true);
		var jwt = CreateValidJwt();
		jwt.Payload.Audiences = ["https://authorization-server.example.com"];
		SetupInvalidJwtValidation(mocks.JwtValidator);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
	}

	/// <summary>
	/// Verifies that with StrictAudienceValidation=true, the token endpoint URL is still accepted.
	/// </summary>
	[Fact]
	public async Task StrictAudienceValidation_WithTokenEndpoint_ShouldSucceed()
	{
		// Arrange
		var (handler, mocks) = CreateHandler(strictAudienceValidation: true);
		var jwt = CreateValidJwt();
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Equal(Subject, grant.AuthSession.Subject);
	}

	private record Mocks(
		Mock<IJsonWebTokenValidator> JwtValidator,
		Mock<IJwtBearerIssuerProvider> IssuerProvider,
		Mock<IRequestInfoProvider> RequestInfoProvider,
		Mock<ISessionIdGenerator> SessionIdGenerator,
		Mock<TimeProvider> TimeProvider);

	private static (JwtBearerGrantHandler Handler, Mocks Mocks) CreateHandler(
		Func<string>? sessionIdFactory = null,
		DateTimeOffset? fixedTime = null,
		string? tokenEndpoint = null,
		string? applicationUri = null,
		bool? strictAudienceValidation = null,
		bool? requireJti = null,
		int? maxJwtSize = null,
		TimeSpan? maxJwtAge = null,
		string[]? allowedAlgorithms = null,
		string[]? allowedTokenTypes = null)
	{
		var jwtValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
		var issuerProvider = new Mock<IJwtBearerIssuerProvider>(MockBehavior.Strict);
		var requestInfoProvider = new Mock<IRequestInfoProvider>(MockBehavior.Strict);
		var sessionIdGenerator = new Mock<ISessionIdGenerator>(MockBehavior.Strict);
		var timeProvider = new Mock<TimeProvider>();

		sessionIdGenerator
			.Setup(g => g.GenerateSessionId())
			.Returns(sessionIdFactory ?? (() => "session_123"));

		timeProvider
			.Setup(t => t.GetUtcNow())
			.Returns(fixedTime ?? DateTimeOffset.UtcNow);

		var options = new JwtBearerOptions { RequireJti = requireJti ?? false };
		if (strictAudienceValidation.HasValue)
			options = options with { StrictAudienceValidation = strictAudienceValidation.Value };
		if (maxJwtSize.HasValue)
			options = options with { MaxJwtSize = maxJwtSize.Value };
		if (maxJwtAge.HasValue)
			options = options with { MaxJwtAge = maxJwtAge.Value };
		if (allowedTokenTypes != null)
			options = options with { AllowedTokenTypes = allowedTokenTypes };

		issuerProvider
			.Setup(p => p.Options)
			.Returns(options);

		issuerProvider
			.Setup(p => p.GetTrustedIssuerAsync(It.IsAny<string>()))
			.ReturnsAsync((TrustedIssuer?)null);

		requestInfoProvider
			.Setup(r => r.RequestUri)
			.Returns(tokenEndpoint ?? "https://authorization-server.example.com/token");

		requestInfoProvider
			.Setup(r => r.ApplicationUri)
			.Returns(applicationUri ?? "https://authorization-server.example.com");

		requestInfoProvider
			.Setup(r => r.RemoteIpAddress)
			.Returns(System.Net.IPAddress.Parse("192.168.1.100"));

		var logger = new Mock<Microsoft.Extensions.Logging.ILogger<JwtBearerGrantHandler>>();

		var handler = new JwtBearerGrantHandler(
			jwtValidator.Object,
			issuerProvider.Object,
			requestInfoProvider.Object,
			sessionIdGenerator.Object,
			timeProvider.Object,
			logger.Object);

		return (handler, new Mocks(jwtValidator, issuerProvider, requestInfoProvider, sessionIdGenerator, timeProvider));
	}

	private static JsonWebToken CreateValidJwt()
	{
		return new JsonWebToken
		{
			Header = new JsonWebTokenHeader(new JsonObject()) { Algorithm = "RS256" },
			Payload = new JsonWebTokenPayload(new JsonObject())
			{
				Subject = Subject,
				Issuer = Issuer,
				IssuedAt = DateTimeOffset.UtcNow,
				ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
				Audiences = ["https://authorization-server.example.com/token"]
			}
		};
	}

	private static void SetupValidJwtValidation(Mock<IJsonWebTokenValidator> validator, JsonWebToken jwt)
	{
		validator
			.Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
			.ReturnsAsync(Result<JsonWebToken, JwtValidationError>.Success(jwt));
	}

	private static void SetupInvalidJwtValidation(Mock<IJsonWebTokenValidator> validator)
	{
		validator
			.Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
			.ReturnsAsync(Result<JsonWebToken, JwtValidationError>.Failure(new JwtValidationError(JwtError.InvalidToken, "Token expired")));
	}

	#region Security Tests - RFC 7523 Compliance

	/// <summary>
	/// Verifies that JWTs signed with disallowed algorithms are rejected.
	/// This prevents algorithm substitution attacks where an attacker might use "none" or weaker algorithms.
	/// Per RFC 7523 Section 3: Only secure algorithms should be accepted.
	/// </summary>
	[Theory]
	[InlineData("none")]
	[InlineData("HS256")]
	[InlineData("HS384")]
	public async Task AlgorithmSubstitution_WithDisallowedAlgorithm_ShouldReject(string algorithm)
	{
		// Arrange
		var (handler, mocks) = CreateHandler(allowedAlgorithms: ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]);
		var jwt = CreateValidJwt();
		jwt.Header.Algorithm = algorithm;
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		Assert.Contains("algorithm", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Verifies that JWTs signed with allowed algorithms are accepted.
	/// </summary>
	[Theory]
	[InlineData("RS256")]
	[InlineData("ES256")]
	public async Task AlgorithmValidation_WithAllowedAlgorithm_ShouldSucceed(string algorithm)
	{
		// Arrange
		var (handler, mocks) = CreateHandler(allowedAlgorithms: ["RS256", "ES256"]);
		var jwt = CreateValidJwt();
		jwt.Header.Algorithm = algorithm;
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Equal(Subject, grant.AuthSession.Subject);
	}

	/// <summary>
	/// Verifies that replay attacks are detected when the same jti is used twice.
	/// Per RFC 7523 Section 5.2: JTI values MUST be unique to prevent replay attacks.
	/// </summary>
	[Fact]
	public async Task ReplayAttack_WithReusedJti_ShouldReject()
	{
		// Arrange
		var (handler, mocks) = CreateHandler(requireJti: true);
		var jwt = CreateValidJwt();
		jwt.Payload.JwtId = "unique-jti-12345";
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer);
		mocks.IssuerProvider
			.Setup(p => p.IsReplayedAsync("unique-jti-12345"))
			.ReturnsAsync(true);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		Assert.Contains("already been used", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Verifies that JWTs without jti are rejected when RequireJti is enabled.
	/// Per RFC 7523 Section 5.2: JTI claim is recommended for replay protection.
	/// </summary>
	[Fact]
	public async Task ReplayProtection_WithMissingJti_WhenRequired_ShouldReject()
	{
		// Arrange
		var (handler, mocks) = CreateHandler(requireJti: true);
		var jwt = CreateValidJwt();
		jwt.Payload.JwtId = null;
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		Assert.Contains("jti", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Verifies that assertions exceeding MaxJwtSize are rejected.
	/// This prevents denial-of-service attacks via excessively large JWTs.
	/// </summary>
	[Fact]
	public async Task MaxJwtSize_WithOversizedAssertion_ShouldReject()
	{
		// Arrange
		var (handler, _) = CreateHandler(maxJwtSize: 100);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = new string('x', 150),
			Scope = ["api.read"]
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		Assert.Contains("size", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Verifies that scopes outside the issuer's allowed scopes are rejected.
	/// Per TrustedIssuer configuration: Only pre-authorized scopes should be granted.
	/// </summary>
	[Fact]
	public async Task ScopeRestriction_WithUnauthorizedScope_ShouldReject()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt = CreateValidJwt();
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer, allowedScopes: ["api.read"]);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion,
			Scope = ["api.read", "api.write", "admin"]
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidScope, error.Error);
	}

	/// <summary>
	/// Verifies that scopes within the issuer's allowed scopes are accepted.
	/// </summary>
	[Fact]
	public async Task ScopeRestriction_WithAuthorizedScopes_ShouldSucceed()
	{
		// Arrange
		var (handler, mocks) = CreateHandler();
		var jwt = CreateValidJwt();
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer, allowedScopes: ["api.read", "api.write"]);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion,
			Scope = ["api.read"]
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Equal(["api.read"], grant.Context.Scope);
	}

	/// <summary>
	/// Verifies that JWTs older than MaxJwtAge are rejected.
	/// Per RFC 7523 Section 3: Authorization server MAY reject JWTs with iat too far in the past.
	/// </summary>
	[Fact]
	public async Task MaxJwtAge_WithOldJwt_ShouldReject()
	{
		// Arrange
		var fixedTime = new DateTimeOffset(2024, 11, 20, 15, 30, 0, TimeSpan.Zero);
		var (handler, mocks) = CreateHandler(
			fixedTime: fixedTime,
			maxJwtAge: TimeSpan.FromMinutes(10));
		var jwt = CreateValidJwt();
		jwt.Payload.IssuedAt = fixedTime.AddMinutes(-30);
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		Assert.Contains("too old", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Verifies that JWTs within MaxJwtAge are accepted.
	/// </summary>
	[Fact]
	public async Task MaxJwtAge_WithFreshJwt_ShouldSucceed()
	{
		// Arrange
		var fixedTime = new DateTimeOffset(2024, 11, 20, 15, 30, 0, TimeSpan.Zero);
		var (handler, mocks) = CreateHandler(
			fixedTime: fixedTime,
			maxJwtAge: TimeSpan.FromMinutes(10));
		var jwt = CreateValidJwt();
		jwt.Payload.IssuedAt = fixedTime.AddMinutes(-5);
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Equal(Subject, grant.AuthSession.Subject);
	}

	/// <summary>
	/// Verifies that JWTs without 'iat' claim are rejected when MaxJwtAge is configured.
	/// Prevents attackers from bypassing age validation by omitting the iat claim.
	/// </summary>
	[Fact]
	public async Task MaxJwtAge_WithMissingIat_ShouldReject()
	{
		// Arrange
		var fixedTime = new DateTimeOffset(2024, 11, 20, 15, 30, 0, TimeSpan.Zero);
		var (handler, mocks) = CreateHandler(
			fixedTime: fixedTime,
			maxJwtAge: TimeSpan.FromMinutes(10));
		var jwt = CreateValidJwt();
		jwt.Payload.IssuedAt = null;
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		Assert.Contains("iat", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Verifies that JWTs with disallowed token types are rejected.
	/// This prevents token confusion attacks in multi-token environments.
	/// </summary>
	[Theory]
	[InlineData("at+jwt")]
	[InlineData("id_token+jwt")]
	[InlineData(null)]
	public async Task TokenTypeValidation_WithDisallowedType_ShouldReject(string? tokenType)
	{
		// Arrange
		var (handler, mocks) = CreateHandler(allowedTokenTypes: ["JWT"]);
		var jwt = CreateValidJwt();
		jwt.Header.Type = tokenType;
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
		Assert.Contains("token type", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Verifies that JWTs with allowed token types are accepted (case-insensitive).
	/// </summary>
	[Theory]
	[InlineData("JWT")]
	[InlineData("jwt")]
	[InlineData("Jwt")]
	public async Task TokenTypeValidation_WithAllowedType_ShouldSucceed(string tokenType)
	{
		// Arrange
		var (handler, mocks) = CreateHandler(allowedTokenTypes: ["JWT"]);
		var jwt = CreateValidJwt();
		jwt.Header.Type = tokenType;
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Equal(Subject, grant.AuthSession.Subject);
	}

	/// <summary>
	/// Verifies that when AllowedTokenTypes is empty, no type restriction is enforced.
	/// </summary>
	[Theory]
	[InlineData("JWT")]
	[InlineData("at+jwt")]
	[InlineData(null)]
	public async Task TokenTypeValidation_WhenNotConfigured_ShouldAcceptAny(string? tokenType)
	{
		// Arrange
		var (handler, mocks) = CreateHandler(allowedTokenTypes: []);
		var jwt = CreateValidJwt();
		jwt.Header.Type = tokenType;
		SetupValidJwtValidation(mocks.JwtValidator, jwt);
		SetupTrustedIssuer(mocks.IssuerProvider, Issuer);
		var clientInfo = new ClientInfo(ClientId);
		var tokenRequest = new TokenRequest
		{
			GrantType = GrantTypes.JwtBearer,
			Assertion = Assertion
		};

		// Act
		var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

		// Assert
		Assert.True(result.TryGetSuccess(out var grant));
		Assert.Equal(Subject, grant.AuthSession.Subject);
	}

	#endregion

	private static void SetupTrustedIssuer(
		Mock<IJwtBearerIssuerProvider> issuerProvider,
		string issuer,
		string[]? allowedAlgorithms = null,
		string[]? allowedScopes = null)
	{
		var trustedIssuer = new TrustedIssuer
		{
			Issuer = issuer,
			JwksUri = new Uri("https://trusted-idp.example.com/.well-known/jwks.json"),
			AllowedAlgorithms = allowedAlgorithms ?? ["RS256", "ES256"],
			AllowedScopes = allowedScopes
		};

		issuerProvider
			.Setup(p => p.GetTrustedIssuerAsync(issuer))
			.ReturnsAsync(trustedIssuer);

		issuerProvider
			.Setup(p => p.IsReplayedAsync(It.IsAny<string>()))
			.ReturnsAsync(false);

		issuerProvider
			.Setup(p => p.MarkAsUsedAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset?>()))
			.Returns(Task.CompletedTask);
	}
}
