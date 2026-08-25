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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens;
using System.Collections.Generic;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens;

/// <summary>
/// Unit tests for <see cref="AccessTokenService"/> verifying access token creation and validation
/// as defined in OAuth 2.0 (RFC 6749) and OpenID Connect specifications.
/// Tests cover token lifecycle, JWT formatting, claim embedding, and authentication.
/// </summary>
public class AccessTokenServiceTests
{
    private static readonly string Issuer = TestConstants.DefaultIssuer.OriginalString;
    private const string ClientId = "test_client_123";
    private const string UserId = "user_456";
    private const string SessionId = "session_789";
    private const string TokenId = "token_abc123";
    private const string EncodedToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJzdWIiOiJ1c2VyXzQ1NiJ9.signature";

    private readonly Mock<IAuthServiceJwtFormatter> _jwtFormatter;
    private readonly AccessTokenService _service;
    private readonly DateTimeOffset _currentTime = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

    public AccessTokenServiceTests()
    {
        var issuerProvider = new Mock<IIssuerProvider>(MockBehavior.Strict);
        issuerProvider.Setup(p => p.GetIssuer()).Returns(Issuer);

        var timeProvider = new FakeTimeProvider(_currentTime);

        var tokenIdGenerator = new Mock<ITokenIdGenerator>(MockBehavior.Strict);
        tokenIdGenerator.Setup(g => g.GenerateTokenId()).Returns(TokenId);

        _jwtFormatter = new Mock<IAuthServiceJwtFormatter>(MockBehavior.Strict);

        // These tests exercise only public clients (default SubjectType), so a converter with no pairwise settings is
        // the exact production path: Convert and ConvertBack both pass the subject through unchanged.
        _service = new AccessTokenService(
            issuerProvider.Object,
            timeProvider,
            tokenIdGenerator.Object,
            _jwtFormatter.Object,
            new SubjectTypeConverter(),
            Options.Create(new OidcOptions()),
            new AudienceKeyResolver(NoResources, NoResourceKeys));
    }

    /// <summary>
    /// A registry with nothing registered: these tests request no resource, so the audience-key lookup never
    /// reaches it. Strict mocks would be equivalent here and noisier.
    /// </summary>
    private static IResourceManager NoResources => Mock.Of<IResourceManager>();

    private static IResourceKeysProvider NoResourceKeys => Mock.Of<IResourceKeysProvider>();

    /// <summary>
    /// Verifies that CreateAccessTokenAsync generates a JWT with correct header fields:
    /// - Type: "at+jwt" (access token type per RFC 9068)
    /// - Algorithm: "RS256" (RSA-SHA256 signature)
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldSetCorrectJwtHeader()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(JsonWebTokenTypes.AccessToken, capturedToken!.Header.Type);
        Assert.Equal(SigningAlgorithms.RS256, capturedToken.Header.Algorithm);
    }

    /// <summary>
    /// Verifies that CreateAccessTokenAsync generates a JWT payload with correct timestamps:
    /// - IssuedAt (iat): Current time
    /// - NotBefore (nbf): Current time
    /// - ExpiresAt (exp): Current time + client's AccessTokenExpiresIn
    /// - Issuer (iss): From IIssuerProvider
    /// - JwtId (jti): Unique token identifier from ITokenIdGenerator
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldSetCorrectTimestampsAndMetadata()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo(accessTokenExpiresIn: TimeSpan.FromMinutes(30));

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(_currentTime, capturedToken!.Payload.IssuedAt);
        Assert.Equal(_currentTime, capturedToken.Payload.NotBefore);
        Assert.Equal(_currentTime.AddMinutes(30), capturedToken.Payload.ExpiresAt);
        Assert.Equal(Issuer, capturedToken.Payload.Issuer);
        Assert.Equal(TokenId, capturedToken.Payload.JwtId);
    }

    /// <summary>
    /// Verifies that CreateAccessTokenAsync applies AuthSession claims to the JWT payload:
    /// - Subject (sub): User identifier
    /// - SessionId (sid): Authentication session identifier
    /// - AuthenticationTime (auth_time): When user authenticated
    /// - IdentityProvider (idp): Identity provider used for authentication
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldApplyAuthSessionClaims()
    {
        // Arrange
        var authTime = _currentTime.AddMinutes(-10);
        var authSession = new AuthSession(
            Subject: UserId,
            SessionId: SessionId,
            AuthenticationTime: authTime,
            IdentityProvider: "google");

        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(UserId, capturedToken!.Payload.Subject);
        Assert.Equal(SessionId, capturedToken.Payload.SessionId);
        Assert.Equal(authTime, capturedToken.Payload.AuthenticationTime);
        Assert.Equal("google", capturedToken.Payload.IdentityProvider);
    }

    /// <summary>
    /// Verifies that CreateAccessTokenAsync applies AuthorizationContext claims to the JWT payload:
    /// - ClientId (client_id): OAuth client identifier
    /// - Scope (scope): Granted scopes
    /// - Audiences (aud): Resource servers that can accept this token
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldApplyAuthorizationContextClaims()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var scopes = new[] { Scopes.OpenId, Scopes.Profile, Scopes.Email };
        var resources = new[] { new Uri("https://api.example.com"), new Uri("https://api2.example.com") };
        var authContext = new AuthorizationContext(ClientId, scopes, null)
        {
            Resources = resources
        };
        var clientInfo = CreateClientInfo();

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(ClientId, capturedToken!.Payload.ClientId);
        Assert.Equal(scopes, capturedToken.Payload.Scope);
        Assert.Equal(["https://api.example.com", "https://api2.example.com"], capturedToken.Payload.Audiences);
    }

    /// <summary>
    /// Verifies that when no Resources are specified in AuthorizationContext, the audience is the issuer.
    /// RFC 9068 Section 4 has a resource server reject a token whose audience does not name it, so the value
    /// standing in for an unstated resource has to name a real consumer: with nothing requested, that is this
    /// server, reached through UserInfo and introspection.
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_WithoutResources_ShouldUseIssuerAsAudience()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = new AuthorizationContext(ClientId, [Scopes.OpenId], null);
        var clientInfo = CreateClientInfo();

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal([Issuer], capturedToken!.Payload.Audiences);
    }

    /// <summary>
    /// Verifies that CreateAccessTokenAsync includes additional claims from AuthSession
    /// in the JWT payload (custom claims beyond standard OIDC claims).
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldIncludeAdditionalClaims()
    {
        // Arrange
        var authSession = new AuthSession(
            Subject: UserId,
            SessionId: SessionId,
            AuthenticationTime: _currentTime.AddMinutes(-10),
            IdentityProvider: "local")
        {
            AdditionalClaims = new JsonObject
            {
                ["department"] = "Engineering",
                ["employee_id"] = "EMP123",
                ["roles"] = new JsonArray("admin", "developer")
            }
        };

        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal("Engineering", capturedToken!.Payload["department"]?.GetValue<string>());
        Assert.Equal("EMP123", capturedToken.Payload["employee_id"]?.GetValue<string>());
        var roles = capturedToken.Payload["roles"]?.AsArray();
        Assert.NotNull(roles);
        Assert.Equal(2, roles!.Count);
        Assert.Equal("admin", roles[0]?.GetValue<string>());
        Assert.Equal("developer", roles[1]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies that CreateAccessTokenAsync returns an EncodedJsonWebToken
    /// containing both the JsonWebToken object and its encoded string representation.
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldReturnEncodedToken()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .ReturnsAsync(EncodedToken);

        // Act
        var result = await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Token);
        Assert.Equal(EncodedToken, result.EncodedJwt);
    }

    /// <summary>
    /// Verifies that AuthenticateByAccessTokenAsync correctly reconstructs AuthSession
    /// from JWT payload claims.
    /// </summary>
    [Fact]
    public async Task AuthenticateByAccessToken_ShouldReconstructAuthSession()
    {
        // Arrange
        var authTime = _currentTime.AddMinutes(-5);
        var jwt = new JsonWebToken
        {
            Payload =
            {
                Subject = UserId,
                SessionId = SessionId,
                AuthenticationTime = authTime,
                IdentityProvider = "local",
                ClientId = ClientId,
                Scope = [Scopes.OpenId],
                Email = "user@example.com",
                EmailVerified = true
            }
        };

        // Act
        var (authSession, _) = (await _service.AuthenticateByAccessTokenAsync(jwt, CreateClientInfo())).GetSuccess();

        // Assert
        Assert.Equal(UserId, authSession.Subject);
        Assert.Equal(SessionId, authSession.SessionId);
        Assert.Equal(authTime, authSession.AuthenticationTime);
        Assert.Equal("local", authSession.IdentityProvider);
        Assert.Equal("user@example.com", authSession.Email);
        Assert.True(authSession.EmailVerified);
    }

    /// <summary>
    /// Verifies that AuthenticateByAccessTokenAsync correctly reconstructs AuthorizationContext
    /// from JWT payload claims.
    /// </summary>
    [Fact]
    public async Task AuthenticateByAccessToken_ShouldReconstructAuthorizationContext()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId, Scopes.Profile };
        var jwt = new JsonWebToken
        {
            Payload =
            {
                Subject = UserId,
                SessionId = SessionId,
                AuthenticationTime = _currentTime,
                IdentityProvider = "local",
                ClientId = ClientId,
                Scope = scopes,
                Audiences = ["https://api.example.com/"]
            }
        };

        // Act
        var (_, authContext) = (await _service.AuthenticateByAccessTokenAsync(jwt, CreateClientInfo())).GetSuccess();

        // Assert
        Assert.Equal(ClientId, authContext.ClientId);
        Assert.Equal(scopes, authContext.Scope);
        Assert.NotNull(authContext.Resources);
        Assert.Single(authContext.Resources!);
        Assert.Equal("https://api.example.com/", authContext.Resources![0].ToString());
    }

    /// <summary>
    /// Verifies that when audience equals client_id (self-audience pattern),
    /// AuthenticateByAccessTokenAsync sets Resources to null.
    /// </summary>
    [Fact]
    public async Task AuthenticateByAccessToken_WithSelfAudience_ShouldSetResourcesNull()
    {
        // Arrange
        var jwt = new JsonWebToken
        {
            Payload =
            {
                Subject = UserId,
                SessionId = SessionId,
                AuthenticationTime = _currentTime,
                IdentityProvider = "local",
                ClientId = ClientId,
                Scope = [Scopes.OpenId],
                Audiences = [ClientId] // Self-audience
            }
        };

        // Act
        var (_, authContext) = (await _service.AuthenticateByAccessTokenAsync(jwt, CreateClientInfo())).GetSuccess();

        // Assert
        Assert.Null(authContext.Resources);
    }

    /// <summary>
    /// Verifies that AuthenticateByAccessTokenAsync correctly reconstructs additional claims
    /// from the JWT payload (custom claims beyond standard OIDC claims).
    /// </summary>
    [Fact]
    public async Task AuthenticateByAccessToken_ShouldReconstructAdditionalClaims()
    {
        // Arrange
        var jwt = new JsonWebToken
        {
            Payload =
            {
                Subject = UserId,
                SessionId = SessionId,
                AuthenticationTime = _currentTime,
                IdentityProvider = "local",
                ClientId = ClientId,
                Scope = [Scopes.OpenId],
                ["department"] = "Engineering",
                ["employee_id"] = "EMP123"
            }
        };

        // Act
        var (authSession, _) = (await _service.AuthenticateByAccessTokenAsync(jwt, CreateClientInfo())).GetSuccess();

        // Assert
        Assert.NotNull(authSession.AdditionalClaims);
        Assert.Equal("Engineering", authSession.AdditionalClaims!["department"]?.GetValue<string>());
        Assert.Equal("EMP123", authSession.AdditionalClaims["employee_id"]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies that AccessTokenService respects different token expiration times
    /// based on client configuration.
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_WithCustomExpiration_ShouldRespectClientConfig()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var customExpiration = TimeSpan.FromHours(2);
        var clientInfo = CreateClientInfo(accessTokenExpiresIn: customExpiration);

        JsonWebToken? capturedToken = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((jwt, _) => capturedToken = jwt)
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        Assert.NotNull(capturedToken);
        Assert.Equal(_currentTime + customExpiration, capturedToken!.Payload.ExpiresAt);
    }

    /// <summary>
    /// A pairwise access token whose 'sub' does not open for the presenting client (a foreign-sector or pre-change
    /// token) is rejected as invalid_token rather than faulting: recovery returns a failure result, not an exception.
    /// </summary>
    [Fact]
    public async Task AuthenticateByAccessToken_PairwiseSubjectDoesNotOpen_ReturnsInvalidToken()
    {
        // Arrange: a service with real pairwise settings, and a 'sub' that is a valid pseudonym for a DIFFERENT
        // sector, so it cannot open for the presenting client's sector.
        var converter = new SubjectTypeConverter(
            new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) });
        var service = new AccessTokenService(
            Mock.Of<IIssuerProvider>(),
            new FakeTimeProvider(_currentTime),
            Mock.Of<ITokenIdGenerator>(),
            Mock.Of<IAuthServiceJwtFormatter>(),
            converter,
            Options.Create(new OidcOptions()),
            new AudienceKeyResolver(NoResources, NoResourceKeys));

        var presentingClient = new ClientInfo(ClientId)
        {
            SubjectType = SubjectTypes.Pairwise,
            SectorIdentifier = "sector.example.com",
        };
        var foreignSectorSub = converter.Convert("real-user", new ClientInfo("other")
        {
            SubjectType = SubjectTypes.Pairwise,
            SectorIdentifier = "other.example.com",
        });
        var jwt = new JsonWebToken
        {
            Payload =
            {
                Subject = foreignSectorSub,
                SessionId = SessionId,
                AuthenticationTime = _currentTime,
                IdentityProvider = "local",
                ClientId = ClientId,
                Scope = [Scopes.OpenId],
            },
        };

        // Act
        var result = await service.AuthenticateByAccessTokenAsync(jwt, presentingClient);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
    }

    /// <summary>
    /// Verifies that the JWT formatter is called exactly once during token creation
    /// with the correctly constructed JWT.
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ShouldCallFormatterOnce()
    {
        // Arrange
        var authSession = CreateAuthSession();
        var authContext = CreateAuthorizationContext();
        var clientInfo = CreateClientInfo();

        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .ReturnsAsync(EncodedToken);

        // Act
        await _service.CreateAccessTokenAsync(authSession, authContext, clientInfo);

        // Assert
        _jwtFormatter.Verify(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()), Times.Once);
    }

    // Helper methods to create test objects

    private static AuthSession CreateAuthSession() =>
        new(
            Subject: UserId,
            SessionId: SessionId,
            AuthenticationTime: new DateTimeOffset(2024, 1, 15, 11, 50, 0, TimeSpan.Zero),
            IdentityProvider: "local");

    private static AuthorizationContext CreateAuthorizationContext() =>
        new(ClientId, [Scopes.OpenId, Scopes.Profile], null);

    private static ClientInfo CreateClientInfo(TimeSpan? accessTokenExpiresIn = null)
    {
        var clientInfo = new ClientInfo(ClientId);
        if (accessTokenExpiresIn.HasValue)
            clientInfo.AccessTokenExpiresIn = accessTokenExpiresIn.Value;
        return clientInfo;
    }

    // Encrypting to the audience rather than to this server

    private static readonly Uri OrdersApi = new("https://orders.example.com");
    private static readonly Uri BillingApi = new("https://billing.example.com");

    /// <summary>
    /// Builds a service whose resource registry answers for the given resources, each with the encryption keys
    /// listed for it. A resource mapped to an empty array is registered but publishes no key.
    /// </summary>
    private AccessTokenService CreateServiceWithResources(
        Dictionary<Uri, JsonWebKey[]> resources)
    {
        var manager = new Mock<IResourceManager>(MockBehavior.Strict);
        var keys = new Mock<IResourceKeysProvider>(MockBehavior.Strict);

        foreach (var (uri, resourceKeys) in resources)
        {
            var definition = new ResourceDefinition(uri);
            var captured = definition;
            manager.Setup(m => m.TryGet(uri, out captured)).Returns(true);
            keys.Setup(k => k.GetEncryptionKeys(definition)).Returns(resourceKeys.ToAsyncEnumerable());
        }

        var issuerProvider = new Mock<IIssuerProvider>(MockBehavior.Strict);
        issuerProvider.Setup(p => p.GetIssuer()).Returns(Issuer);

        var tokenIdGenerator = new Mock<ITokenIdGenerator>(MockBehavior.Strict);
        tokenIdGenerator.Setup(g => g.GenerateTokenId()).Returns(TokenId);

        return new AccessTokenService(
            issuerProvider.Object,
            new FakeTimeProvider(_currentTime),
            tokenIdGenerator.Object,
            _jwtFormatter.Object,
            new SubjectTypeConverter(),
            Options.Create(new OidcOptions()),
            new AudienceKeyResolver(manager.Object, keys.Object));
    }

    private static AuthorizationContext ContextFor(params Uri[] resources) =>
        new(ClientId, [Scopes.OpenId], null) { Resources = resources };

    /// <summary>
    /// A resource that publishes an encryption key gets the access token encrypted to it, so the party named
    /// in <c>aud</c> can read the token minted for it. Without this the token is encrypted to this server's
    /// own key, which the audience cannot decrypt: it holds only the published public half.
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ResourcePublishesKey_EncryptsToThatKey()
    {
        var resourceKey = new RsaJsonWebKey { KeyId = "orders-enc" };
        var service = CreateServiceWithResources(new() { [OrdersApi] = [resourceKey] });

        ServiceJwtEncryption? capturedPolicy = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((_, policy) => capturedPolicy = policy)
            .ReturnsAsync(EncodedToken);

        await service.CreateAccessTokenAsync(
            CreateAuthSession(), ContextFor(OrdersApi), CreateClientInfo());

        Assert.NotNull(capturedPolicy);
        Assert.Same(resourceKey, capturedPolicy!.Key);
    }

    /// <summary>
    /// A resource that publishes no key leaves the policy alone, so the token follows the server's own
    /// settings exactly as it did before resources could carry keys. Publishing nothing is how a resource says
    /// a signed JWS is what it expects.
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_ResourcePublishesNoKey_LeavesPolicyUntouched()
    {
        var service = CreateServiceWithResources(new() { [OrdersApi] = [] });

        ServiceJwtEncryption? capturedPolicy = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((_, policy) => capturedPolicy = policy)
            .ReturnsAsync(EncodedToken);

        await service.CreateAccessTokenAsync(
            CreateAuthSession(), ContextFor(OrdersApi), CreateClientInfo());

        Assert.NotNull(capturedPolicy);
        Assert.Null(capturedPolicy!.Key);
    }

    /// <summary>
    /// Two audiences that each publish a key have no correct answer, because compact JWE serialization carries
    /// a single recipient. Encrypting to one would leave the token unreadable to the other while looking
    /// successful, so the request is refused instead.
    /// </summary>
    [Fact]
    public async Task CreateAccessToken_SeveralResourcesPublishKeys_Throws()
    {
        var service = CreateServiceWithResources(new()
        {
            [OrdersApi] = [new RsaJsonWebKey { KeyId = "orders-enc" }],
            [BillingApi] = [new RsaJsonWebKey { KeyId = "billing-enc" }],
        });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.CreateAccessTokenAsync(
                CreateAuthSession(), ContextFor(OrdersApi, BillingApi), CreateClientInfo()));

        Assert.Contains(OrdersApi.OriginalString, exception.Message);
        Assert.Contains(BillingApi.OriginalString, exception.Message);
    }

    // Narrowing authorization_details to the audience the token is addressed to

    private static AuthorizationContext ContextAddressedTo(Uri[] resources, JsonArray details) =>
        new(ClientId, [Scopes.OpenId], null) { Resources = resources, AuthorizationDetails = details };

    private static AuthorizationContext ContextWithoutResource(JsonArray details) =>
        new(ClientId, [Scopes.OpenId, Scopes.Profile], null) { AuthorizationDetails = details };

    private static JsonArray DetailsForPayments(params string?[] locations) =>
        new(locations
            .Select(location => location is null
                ? new JsonObject { ["type"] = "payment_initiation" }
                : new JsonObject
                {
                    ["type"] = "payment_initiation",
                    ["locations"] = new JsonArray(location),
                })
            .Cast<JsonNode?>()
            .ToArray());

    private async Task<JsonWebToken> MintAsync(AccessTokenService service, AuthorizationContext context)
    {
        JsonWebToken? captured = null;
        _jwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .Callback<JsonWebToken, ServiceJwtEncryption>((jwt, _) => captured = jwt)
            .ReturnsAsync(EncodedToken);

        await service.CreateAccessTokenAsync(CreateAuthSession(), context, CreateClientInfo());

        Assert.NotNull(captured);
        return captured!;
    }

    /// <summary>
    /// A token minted for one resource server carries only the entries addressed to it.
    /// </summary>
    /// <remarks>
    /// RFC 9396 section 9.1: the authorization details go into the token "filtered to the specific
    /// audience". An entry naming another server describes a permission its bearer cannot exercise here,
    /// and carrying it tells this reader about the end user's other grants for nothing in return.
    ///
    /// The entry carrying no locations survives, which is the half that keeps the filter honest: section
    /// 2.2 makes the member optional, so absence means the entry names no server rather than naming none.
    /// </remarks>
    [Fact]
    public async Task CreateAccessToken_ForOneResource_KeepsOnlyTheDetailsAddressedToIt()
    {
        var service = CreateServiceWithResources(new() { [OrdersApi] = [] });
        var context = ContextAddressedTo(
            [OrdersApi],
            DetailsForPayments(OrdersApi.OriginalString, BillingApi.OriginalString, null));

        var token = await MintAsync(service, context);

        var details = Assert.IsType<JsonArray>(token.Payload.Json[IanaClaimTypes.AuthorizationDetails]);
        var located = details
            .Select(entry => entry?["locations"]?.ToJsonString())
            .ToList();

        Assert.Equal(2, details.Count);
        Assert.Contains($"[\"{OrdersApi.OriginalString}\"]", located);
        Assert.Contains(null, located);
        Assert.DoesNotContain($"[\"{BillingApi.OriginalString}\"]", located);
    }

    /// <summary>
    /// A token whose every entry names another server carries no claim at all.
    /// </summary>
    /// <remarks>
    /// An empty array would say the end user granted nothing, which is false. The member's absence says
    /// this token authorises nothing detail-wise here, which is what happened.
    /// </remarks>
    [Fact]
    public async Task CreateAccessToken_WhenEveryDetailNamesAnotherResource_OmitsTheClaim()
    {
        var service = CreateServiceWithResources(new() { [OrdersApi] = [] });
        var context = ContextAddressedTo([OrdersApi], DetailsForPayments(BillingApi.OriginalString));

        var token = await MintAsync(service, context);

        Assert.Null(token.Payload.Json[IanaClaimTypes.AuthorizationDetails]);
    }

    /// <summary>
    /// With no resource requested, nothing is dropped.
    /// </summary>
    /// <remarks>
    /// The control, and the reason this is not a behaviour change for a deployment that never used resource
    /// indicators. The audience falls back to the issuer, which names this server rather than a resource,
    /// so there is no specific audience for section 9.1 to filter to - and without this test the filter
    /// above would read the same whether it narrowed by audience or simply dropped every located entry.
    /// </remarks>
    [Fact]
    public async Task CreateAccessToken_WithNoResourceRequested_KeepsEveryDetail()
    {
        var context = ContextWithoutResource(
            DetailsForPayments(OrdersApi.OriginalString, BillingApi.OriginalString, null));

        var token = await MintAsync(_service, context);

        var details = Assert.IsType<JsonArray>(token.Payload.Json[IanaClaimTypes.AuthorizationDetails]);
        Assert.Equal(3, details.Count);
        Assert.Equal([Issuer], token.Payload.Audiences);
    }
}
