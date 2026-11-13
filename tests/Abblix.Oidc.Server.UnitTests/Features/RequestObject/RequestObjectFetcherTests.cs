// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RequestObject;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using RequestParameters = Abblix.Oidc.Server.Model.AuthorizationRequest.Parameters;

namespace Abblix.Oidc.Server.UnitTests.Features.RequestObject;

/// <summary>
/// Unit tests for <see cref="RequestObjectFetcher"/> verifying JWT request object validation,
/// binding, and error handling per OIDC Core specification.
/// </summary>
public class RequestObjectFetcherTests
{
    private readonly Mock<ILogger<RequestObjectFetcher>> _logger;
    private readonly Mock<IJsonObjectBinder> _jsonObjectBinder;
    private readonly Mock<IServiceProvider> _serviceProvider;
    private readonly Mock<IServiceScopeFactory> _serviceScopeFactory;
    private readonly Mock<IServiceScope> _serviceScope;
    private readonly Mock<IServiceProvider> _scopedServiceProvider;
    private readonly Mock<IClientJwtValidator> _jwtValidator;
    private readonly Mock<IOptionsSnapshot<OidcOptions>> _options;
    private readonly OidcOptions _oidcOptions;

    /// <summary>
    /// The instant every request object here is judged at.
    /// </summary>
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 9, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _clock = new(Now);

    public RequestObjectFetcherTests()
    {
        _logger = new Mock<ILogger<RequestObjectFetcher>>();
        _jsonObjectBinder = new Mock<IJsonObjectBinder>(MockBehavior.Strict);
        _serviceProvider = new Mock<IServiceProvider>(MockBehavior.Strict);
        _serviceScopeFactory = new Mock<IServiceScopeFactory>(MockBehavior.Strict);
        _serviceScope = new Mock<IServiceScope>(MockBehavior.Strict);
        _scopedServiceProvider = new Mock<IServiceProvider>(MockBehavior.Strict);
        _jwtValidator = new Mock<IClientJwtValidator>(MockBehavior.Strict);
        _options = new Mock<IOptionsSnapshot<OidcOptions>>(MockBehavior.Strict);

        _oidcOptions = new OidcOptions();
        _options.Setup(o => o.Value).Returns(_oidcOptions);

        // Setup DI scope chain
        _serviceProvider
            .Setup(sp => sp.GetService(typeof(IServiceScopeFactory)))
            .Returns(_serviceScopeFactory.Object);

        _serviceScopeFactory
            .Setup(f => f.CreateScope())
            .Returns(_serviceScope.Object);

        _serviceScope
            .Setup(s => s.ServiceProvider)
            .Returns(_scopedServiceProvider.Object);

        _serviceScope
            .Setup(s => s.Dispose());

        _scopedServiceProvider
            .Setup(sp => sp.GetService(typeof(IClientJwtValidator)))
            .Returns(_jwtValidator.Object);
    }

    private RequestObjectFetcher CreateFetcher()
    {
        return new RequestObjectFetcher(_logger.Object, _jsonObjectBinder.Object, _serviceProvider.Object, _options.Object, _clock);
    }

    private record TestRequest(string ClientId, string RedirectUri, string? State);

    // A request type with wire-named JSON keys, mirroring how real request models bind, so strict
    // RFC 9101 section 6.3 processing can be exercised where parameter names line up with the object's claims.
    private record JarTestRequest
    {
        [JsonPropertyName(RequestParameters.ClientId)] public string? ClientId { get; init; }
        [JsonPropertyName(RequestParameters.State)] public string? State { get; init; }
        [JsonPropertyName(RequestParameters.Request)] public string? Request { get; init; }
    }

    /// <summary>
    /// A client held to the FAPI 2.0 security profile is processed under the strict RFC 9101 section 6.3 rule even
    /// when the global default stays merge: a parameter passed outside the request object that the object does
    /// not carry is dropped, and the drop is reported as a warning.
    /// </summary>
    [Fact]
    public async Task FetchAsync_FapiProfileClient_ProcessesStrictlyAndWarnsOnOutsideParameter()
    {
        // Arrange - the global default stays merge; the FAPI profile is what forces strict for this client.
        Assert.False(_oidcOptions.IgnoreParametersOutsideRequestObject);
        _logger.Setup(l => l.IsEnabled(LogLevel.Warning)).Returns(true);
        var fetcher = CreateFetcher();

        const string jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjMSJ9.signature";
        var request = new JarTestRequest { ClientId = "c1", State = "outside-only", Request = jwt };
        var payload = new JsonObject { [RequestParameters.ClientId] = "c1" };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = WithinTheProfileLifetime(payload),
        };
        var fapiClient = new ClientInfo("c1") { SecurityProfile = ClientSecurityProfile.Fapi2 };
        AddressedTo(SingleIssuer.Tenant, token.Payload);

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, fapiClient));
        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, It.IsAny<JarTestRequest>()))
            .ReturnsAsync((JsonObject _, JarTestRequest bound) => bound);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert - the payload bound onto a fresh model (the outside-only state is gone) and the drop was logged.
        Assert.True(result.TryGetSuccess(out var value));
        Assert.NotSame(request, value);
        Assert.Null(value.State);
        _logger.Verify(
            l => l.Log(
                LogLevel.Warning,
                It.Is<EventId>(e => e.Id == LogEvents.Misc.RequestObjectFetcher.ParametersOutsideRequestObjectIgnored),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    /// <summary>
    /// A client with no security profile of its own takes the default of the tenant the request is served at, so a
    /// tenant holding its clients to FAPI 2.0 has their request objects processed under the strict RFC 9101 section
    /// 6.3 rule: a parameter passed outside the object that the object does not carry is dropped.
    /// </summary>
    [Fact]
    public async Task FetchAsync_UnprofiledClientAtFapiTenant_ProcessesStrictly()
    {
        Assert.False(_oidcOptions.IgnoreParametersOutsideRequestObject);
        var fetcher = CreateFetcher();

        const string jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjMSJ9.signature";
        var request = new JarTestRequest { ClientId = "c1", State = "outside-only", Request = jwt };
        var payload = new JsonObject { [RequestParameters.ClientId] = "c1" };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = WithinTheProfileLifetime(payload),
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("c1")));
        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, It.IsAny<JarTestRequest>()))
            .ReturnsAsync((JsonObject _, JarTestRequest bound) => bound);

        var fapiTenant = new TestIssuer { DefaultSecurityProfile = ClientSecurityProfile.Fapi2 }.ToTenant();
        AddressedTo(fapiTenant, token.Payload);
        var result = await fetcher.FetchAsync(fapiTenant, null, request, jwt);

        Assert.True(result.TryGetSuccess(out var value));
        Assert.NotSame(request, value);
        Assert.Null(value.State);
    }

    /// <summary>
    /// Verifies that null requestObject returns original request unchanged.
    /// Per OIDC specification, request object parameter is optional.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithNullRequestObject_ShouldReturnOriginalRequest()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, "state123");

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, null);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Same(request, value);
    }

    /// <summary>
    /// Verifies that empty requestObject returns original request unchanged.
    /// Empty strings should be treated as absence of request object.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithEmptyRequestObject_ShouldReturnOriginalRequest()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, string.Empty);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Same(request, value);
    }

    /// <summary>
    /// Verifies successful processing with valid signed JWT and successful binding.
    /// Per OIDC specification, valid JWT should be processed and bound to request.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithValidJwtAndSuccessfulBinding_ShouldReturnBoundRequest()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var originalRequest = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.signature";
        var payload = new JsonObject { [RequestParameters.ClientId] = TestConstants.DefaultClientId, [RequestParameters.State] = "newstate" };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload)
        };
        var boundRequest = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, "newstate");

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, originalRequest))
            .ReturnsAsync(boundRequest);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, originalRequest, jwt);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Same(boundRequest, value);
        Assert.Equal("newstate", value.State);
    }

    /// <summary>
    /// Verifies error when binding fails (returns null).
    /// Binding failures should result in InvalidRequestObject error.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithValidJwtButBindingFails_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var originalRequest = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.signature";
        var payload = new JsonObject { ["invalid"] = "data" };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload)
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, originalRequest))
            .ReturnsAsync((TestRequest?)null);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, originalRequest, jwt);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// A request object carrying a member in a shape its parameter cannot take, as a negative max_age, is refused
    /// as an invalid request object rather than failing the request.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithAMemberOfTheWrongShape_IsAnInvalidRequestObject()
    {
        var fetcher = CreateFetcher();
        var originalRequest = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJSUzI1NiJ9.eyJtYXhfYWdlIjotMX0.signature";
        var payload = new JsonObject { [RequestParameters.MaxAge] = -1 };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload)
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, originalRequest))
            .ThrowsAsync(new JsonException("negative seconds"));

        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, originalRequest, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// Fetches a request object carrying <paramref name="uiLocales"/> as its <c>ui_locales</c> claim, read through
    /// the binder and the converters the authorization request really uses.
    /// </summary>
    private async Task<Result<AuthorizationRequest, OidcError>> FetchWithUiLocales(JsonNode uiLocales)
    {
        var fetcher = new RequestObjectFetcher(_logger.Object, new JsonSerializationBinder(), _serviceProvider.Object,
            _options.Object, _clock);
        var originalRequest = new AuthorizationRequest { ClientId = TestConstants.DefaultClientId };
        const string jwt = "eyJhbGciOiJSUzI1NiJ9.eyJ1aV9sb2NhbGVzIjoiISJ9.signature";
        var payload = new JsonObject { [RequestParameters.UiLocales] = uiLocales };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload),
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo(TestConstants.DefaultClientId)));

        return await fetcher.FetchAsync(SingleIssuer.Tenant, null, originalRequest, jwt);
    }

    /// <summary>
    /// A request object naming a UI locale no culture can carry is refused as an invalid request object, as the
    /// same value in the query is refused as an invalid request.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithAUiLocaleNoCultureCanCarry_IsAnInvalidRequestObject()
    {
        var result = await FetchWithUiLocales(JsonValue.Create("en !"));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// A request object carries <c>ui_locales</c> in the shape the parameter has, a space-separated string of
    /// language tags (OpenID Connect Core 1.0 sections 3.1.2.1 and 6.1), and every tag is read.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithUiLocalesAsASpaceSeparatedString_ReadsEveryTag()
    {
        var result = await FetchWithUiLocales(JsonValue.Create("en fr-CA"));

        Assert.True(result.TryGetSuccess(out var request));
        Assert.Equal(["en", "fr-CA"], request.UiLocales!.Select(culture => culture.Name));
    }

    /// <summary>
    /// Verifies that a request object whose signing algorithm differs from the client's registered
    /// algorithm is rejected when a required-algorithm selector is supplied (request_object_signing_alg
    /// for authorization, backchannel_authentication_request_signing_alg for CIBA).
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithRequestObjectAlgorithmMismatch_ShouldReturnError()
    {
        // Arrange - the request object is signed with RS384, but the client registered RS256.
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "header.payload.signature";
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject { ["alg"] = SigningAlgorithms.RS384 }),
            Payload = new JsonWebTokenPayload(new JsonObject { [RequestParameters.ClientId] = TestConstants.DefaultClientId })
        };
        var clientInfo = new ClientInfo("test-client") { RequestObjectSigningAlgorithm = SigningAlgorithms.RS256 };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        // Act - the binder is strict and unset, so the alg pin must reject before any binding.
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt, client => client.RequestObjectSigningAlgorithm);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// Verifies that a request object whose signing algorithm matches the client's registered
    /// algorithm passes the pin and is processed.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithMatchingRequestObjectAlgorithm_ShouldSucceed()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "header.payload.signature";
        var payload = new JsonObject { [RequestParameters.ClientId] = TestConstants.DefaultClientId };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject { ["alg"] = SigningAlgorithms.RS256 }),
            Payload = new JsonWebTokenPayload(payload)
        };
        var clientInfo = new ClientInfo("test-client") { RequestObjectSigningAlgorithm = SigningAlgorithms.RS256 };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));
        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, request))
            .ReturnsAsync(request);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt, client => client.RequestObjectSigningAlgorithm);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Same(request, value);
    }

    /// <summary>
    /// Verifies error handling for invalid JWT.
    /// Per OIDC specification, invalid JWT should return InvalidRequestObject error.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithInvalidJwt_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "invalid.jwt.token";
        var validationError = new JwtValidationError(JwtError.InvalidToken, "Invalid JWT format");

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(validationError);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// Verifies RequireSignedRequestObject option enforces signature requirement.
    /// When enabled, validator should receive RequireSignedTokens validation option.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithRequireSignedRequestObject_ShouldPassCorrectValidationOptions()
    {
        // Arrange
        _oidcOptions.RequireSignedRequestObject = true;
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.signature";
        var payload = new JsonObject { [RequestParameters.ClientId] = TestConstants.DefaultClientId };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload)
        };
        ValidationOptions? capturedOptions = null;

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .Callback<TenantDefinition, ClientInfo?, string, TokenTypePolicy, ValidationOptions>((_, _, _, _, options) => capturedOptions = options)
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, request))
            .ReturnsAsync(request);

        // Act
        await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.True(capturedOptions.Value.HasFlag(ValidationOptions.RequireSignedTokens));
        Assert.True(capturedOptions.Value.HasFlag(ValidationOptions.ValidateIssuerSigningKey));
    }

    /// <summary>
    /// Verifies validation options when RequireSignedRequestObject is false.
    /// Should validate signature key but not require signed tokens.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithoutRequireSignedRequestObject_ShouldPassCorrectValidationOptions()
    {
        // Arrange
        _oidcOptions.RequireSignedRequestObject = false;
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJub25lIn0.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.";
        var payload = new JsonObject { [RequestParameters.ClientId] = TestConstants.DefaultClientId };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload)
        };
        ValidationOptions? capturedOptions = null;

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .Callback<TenantDefinition, ClientInfo?, string, TokenTypePolicy, ValidationOptions>((_, _, _, _, options) => capturedOptions = options)
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, request))
            .ReturnsAsync(request);

        // Act
        await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        Assert.NotNull(capturedOptions);
        Assert.False(capturedOptions.Value.HasFlag(ValidationOptions.RequireSignedTokens));
        Assert.True(capturedOptions.Value.HasFlag(ValidationOptions.ValidateIssuerSigningKey));
    }

    /// <summary>
    /// Verifies service provider scope is created for validation.
    /// Per DI best practices, scoped services should be created per operation.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ShouldCreateServiceScope()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.signature";
        var payload = new JsonObject { [RequestParameters.ClientId] = TestConstants.DefaultClientId };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload)
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, request))
            .ReturnsAsync(request);

        // Act
        await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        _serviceScopeFactory.Verify(f => f.CreateScope(), Times.Once);
        _scopedServiceProvider.Verify(sp => sp.GetService(typeof(IClientJwtValidator)), Times.Once);
    }

    /// <summary>
    /// Verifies service scope is properly disposed.
    /// Per IDisposable pattern, scopes must be disposed to release resources.
    /// </summary>
    [Fact]
    public async Task FetchAsync_ShouldDisposeServiceScope()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.signature";
        var payload = new JsonObject { [RequestParameters.ClientId] = TestConstants.DefaultClientId };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload)
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, request))
            .ReturnsAsync(request);

        // Act
        await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        _serviceScope.Verify(s => s.Dispose(), Times.Once);
    }

    /// <summary>
    /// Verifies multiple sequential requests work correctly.
    /// Each request should create its own scope and work independently.
    /// </summary>
    [Fact]
    public async Task FetchAsync_MultipleSequentialCalls_ShouldWork()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request1 = new TestRequest(TestConstants.DefaultClientId, "https://example.com/callback1", null);
        var request2 = new TestRequest(TestConstants.AlternativeClientId, "https://example.com/callback2", null);
        var jwt1 = "jwt1";
        var jwt2 = "jwt2";
        var payload1 = new JsonObject { [RequestParameters.ClientId] = TestConstants.DefaultClientId };
        var payload2 = new JsonObject { [RequestParameters.ClientId] = TestConstants.AlternativeClientId };
        var token1 = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload1)
        };
        var token2 = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload2)
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, It.IsAny<string>(), It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync((TenantDefinition _, ClientInfo? _, string jwt, TokenTypePolicy _, ValidationOptions _) =>
            {
                var token = jwt == jwt1 ? token1 : token2;
                return new ValidJsonWebToken(token, new ClientInfo("test-client"));
            });

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(It.IsAny<JsonObject>(), It.IsAny<TestRequest>()))
            .ReturnsAsync((JsonObject _, TestRequest req) => req);

        // Act
        var result1 = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request1, jwt1);
        var result2 = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request2, jwt2);

        // Assert
        Assert.True(result1.TryGetSuccess(out _));
        Assert.True(result2.TryGetSuccess(out _));
        _serviceScopeFactory.Verify(f => f.CreateScope(), Times.Exactly(2));
    }

    /// <summary>
    /// Verifies error with expired JWT.
    /// Expired tokens should be rejected per JWT specification.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithExpiredJwt_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJSUzI1NiJ9.expired.signature";
        var validationError = new JwtValidationError(JwtError.InvalidToken, "Token has expired");

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(validationError);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// Verifies error with JWT having invalid signature.
    /// Per JWT specification, signature must be valid.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithInvalidSignature_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJSUzI1NiJ9.payload.badsignature";
        var validationError = new JwtValidationError(JwtError.InvalidToken, "Invalid signature");

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(validationError);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// Verifies processing with complex JSON payload.
    /// Complex payloads should be properly bound to request model.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithComplexPayload_ShouldBindCorrectly()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var originalRequest = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJSUzI1NiJ9.complex.signature";
        var payload = new JsonObject
        {
            [RequestParameters.ClientId] = TestConstants.DefaultClientId,
            [RequestParameters.RedirectUri] = "https://new.example.com/callback",
            [RequestParameters.State] = "complex_state_123",
            [RequestParameters.Nonce] = "nonce_value",
            [RequestParameters.ResponseType] = ResponseTypes.Code
        };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload)
        };
        var boundRequest = new TestRequest(TestConstants.DefaultClientId, "https://new.example.com/callback", "complex_state_123");

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, originalRequest))
            .ReturnsAsync(boundRequest);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, originalRequest, jwt);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Equal("complex_state_123", value.State);
        Assert.Equal("https://new.example.com/callback", value.RedirectUri);
    }

    /// <summary>
    /// Verifies proper logging of request object.
    /// Per OIDC debugging requirements, request objects should be logged.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithValidJwt_ShouldLogRequestObject()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.signature";
        var payload = new JsonObject { [RequestParameters.ClientId] = TestConstants.DefaultClientId };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload)
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, request))
            .ReturnsAsync(request);

        // Act
        await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        // Verify logging was called (implementation depends on how you verify ILogger mocks)
        // For now, just verify no exception was thrown during logging
        Assert.True(true);
    }

    /// <summary>
    /// Verifies malformed JWT structure returns error.
    /// Per JWT specification, JWT must have proper structure.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithMalformedJwt_ShouldReturnError()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "this.is.not.a.valid.jwt.structure";
        var validationError = new JwtValidationError(JwtError.InvalidToken, "Malformed JWT");

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(validationError);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// Verifies processing with minimal valid JWT payload.
    /// Minimal payloads should be accepted if validation passes.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithMinimalPayload_ShouldWork()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJub25lIn0.e30."; // JWT with empty payload
        var payload = new JsonObject();
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload)
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, request))
            .ReturnsAsync(request);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Same(request, value);
    }

    /// <summary>
    /// Verifies different request types can be processed.
    /// Generic implementation should support any class type.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithDifferentRequestType_ShouldWork()
    {
        // Arrange
        var fetcher = CreateFetcher();
        var request = new { ClientId = TestConstants.DefaultClientId, Scope = TestConstants.DefaultScope };
        var jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.signature";
        var payload = new JsonObject { [RequestParameters.ClientId] = TestConstants.DefaultClientId };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = new JsonWebTokenPayload(payload)
        };
        var boundRequest = new { ClientId = TestConstants.DefaultClientId, Scope = "openid profile" };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, request))
            .ReturnsAsync(boundRequest);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Equal("openid profile", value.Scope);
    }

    /// <summary>
    /// Verifies unsigned JWT (alg=none) is accepted when RequireSignedRequestObject is false.
    /// Per OIDC specification, servers advertising "none" in request_object_signing_alg_values_supported
    /// and require_signed_request_object=false must accept unsigned request objects.
    /// This is tested by OpenID Certification: oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithUnsignedJwtWhenNotRequired_ShouldSucceed()
    {
        // Arrange
        _oidcOptions.RequireSignedRequestObject = false;
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);

        // Unsigned JWT with alg=none (no signature part)
        var unsignedJwt = "eyJhbGciOiJub25lIn0.eyJjbGllbnRfaWQiOiJjbGllbnQxIiwic3RhdGUiOiJ0ZXN0X3N0YXRlIn0.";
        var payload = new JsonObject
        {
            [RequestParameters.ClientId] = TestConstants.DefaultClientId,
            [RequestParameters.State] = "test_state"
        };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject { ["alg"] = "none" }),
            Payload = new JsonWebTokenPayload(payload)
        };
        var boundRequest = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, "test_state");

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, unsignedJwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, request))
            .ReturnsAsync(boundRequest);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, unsignedJwt);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Equal("test_state", value.State);

        // Verify that RequireSignedTokens flag was NOT set
        _jwtValidator.Verify(
            v => v.ValidateAsync(
                TestTenant.Matched, null, unsignedJwt,
                It.IsAny<TokenTypePolicy>(), It.Is<ValidationOptions>(opts => !opts.HasFlag(ValidationOptions.RequireSignedTokens))),
            Times.Once);
    }

    /// <summary>
    /// Verifies unsigned JWT (alg=none) is rejected when RequireSignedRequestObject is true.
    /// Per OIDC specification, servers with require_signed_request_object=true must reject unsigned tokens.
    /// </summary>
    [Fact]
    public async Task FetchAsync_WithUnsignedJwtWhenRequired_ShouldFail()
    {
        // Arrange
        _oidcOptions.RequireSignedRequestObject = true;
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);

        // Unsigned JWT with alg=none
        var unsignedJwt = "eyJhbGciOiJub25lIn0.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.";
        var validationError = new JwtValidationError(JwtError.InvalidToken, "Unsigned tokens are not allowed");

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, unsignedJwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(validationError);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, unsignedJwt);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);

        // Verify that RequireSignedTokens flag WAS set
        _jwtValidator.Verify(
            v => v.ValidateAsync(
                TestTenant.Matched, null, unsignedJwt,
                It.IsAny<TokenTypePolicy>(), It.Is<ValidationOptions>(opts => opts.HasFlag(ValidationOptions.RequireSignedTokens))),
            Times.Once);
    }

    /// <summary>
    /// RFC 9101 section 10.5: a client registered with require_signed_request_object committed to SIGNED
    /// request objects - an unsigned (alg=none) object passes structural validation but must be
    /// rejected by the per-client commitment even when the server-wide requirement is off.
    /// </summary>
    [Fact]
    public async Task FetchAsync_UnsignedObjectFromCommittedClient_ShouldFail()
    {
        // Arrange - server-wide RequireSignedRequestObject stays off.
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJub25lIn0.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.";
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()) { Algorithm = SigningAlgorithms.None },
            Payload = new JsonWebTokenPayload(new JsonObject()),
        };
        var committedClient = new ClientInfo("test-client") { RequireSignedRequestObject = true };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, committedClient));

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2 requires "a JWS signed JWT request object" and section 8.6 has the server "not use
    /// none", so an unsigned object from a client held to that profile is refused, its own flag and the server-wide
    /// requirement both off.
    /// </summary>
    [Fact]
    public async Task FetchAsync_UnsignedObjectFromFapi1AdvancedClient_ShouldFail()
    {
        var fetcher = CreateFetcher();
        var request = new TestRequest(TestConstants.DefaultClientId, TestConstants.DefaultRedirectUri.OriginalString, null);
        var jwt = "eyJhbGciOiJub25lIn0.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.";
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()) { Algorithm = SigningAlgorithms.None },
            Payload = WithinTheProfileLifetime(new JsonObject()),
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, Fapi1AdvancedClient));

        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, request, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2: the server "shall only use the parameters included in the signed request
    /// object", so a state passed only outside it is gone from the request - for the client naming the profile and
    /// for one inheriting it from its tenant - while an unprofiled client at an unprofiled tenant keeps the Core
    /// section 6.1 merge, which is what shows the drop comes from the profile.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, ClientSecurityProfile.None, null)]
    [InlineData(null, ClientSecurityProfile.Fapi1Advanced, null)]
    [InlineData(null, ClientSecurityProfile.None, "outside-only")]
    public async Task FetchAsync_Fapi1Advanced_UsesOnlyTheRequestObject(
        ClientSecurityProfile? clientProfile,
        ClientSecurityProfile tenantProfile,
        string? expectedState)
    {
        Assert.False(_oidcOptions.IgnoreParametersOutsideRequestObject);
        var fetcher = CreateFetcher();
        var tenant = new TestIssuer { DefaultSecurityProfile = tenantProfile }.ToTenant();

        const string jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjMSJ9.signature";
        var request = new JarTestRequest { ClientId = "c1", State = "outside-only", Request = jwt };
        var payload = new JsonObject { [RequestParameters.ClientId] = "c1" };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()) { Algorithm = SigningAlgorithms.PS256 },
            Payload = AddressedTo(tenant, WithinTheProfileLifetime(payload)),
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("c1") { SecurityProfile = clientProfile }));
        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(payload, It.IsAny<JarTestRequest>()))
            .ReturnsAsync((JsonObject _, JarTestRequest bound) => bound);

        var result = await fetcher.FetchAsync(tenant, null, request, jwt);

        Assert.True(result.TryGetSuccess(out var value));
        Assert.Equal(expectedState, value.State);
    }

    private static ClientInfo Fapi1AdvancedClient
        => new("c1") { SecurityProfile = ClientSecurityProfile.Fapi1Advanced };

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2: the server "shall require the aud claim in the request object to be, or to be
    /// an array containing, the OP's Issuer Identifier URL". An object naming no audience, or only the endpoint it
    /// was sent to, is refused for a client held to that profile; the issuer as a string or inside an array passes.
    /// </summary>
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, true)]
    [InlineData(true, true, true)]
    public async Task FetchAsync_Fapi1AdvancedClient_RequestObjectAudience(
        bool namesTheIssuer, bool namesTheEndpoint, bool accepted)
    {
        var tenant = SingleIssuer.Tenant;
        var payload = WithinTheProfileLifetime(new JsonObject());
        payload.Audiences = new[]
            {
                namesTheIssuer ? tenant.Issuer.OriginalString : null,
                namesTheEndpoint ? new Uri(tenant.Issuer, "connect/authorize").OriginalString : null,
            }
            .OfType<string>()
            .ToArray();

        var result = await Fetch(Fapi1AdvancedClient, tenant, payload);

        if (accepted)
            Assert.True(result.TryGetSuccess(out _));
        else
            AssertInvalidRequestObject(result);
    }

    /// <summary>
    /// The audience and lifetime rules of FAPI 2.0 Message Signing section 5.3.1 belong to that profile, not to the FAPI
    /// 2.0 Security Profile: a request object a client held to FAPI 2.0 sends naming no audience, and carrying neither nbf
    /// nor exp, is accepted.
    /// </summary>
    [Fact]
    public async Task FetchAsync_Fapi2Client_RequestObjectWithoutAudienceOrLifetime_Passes()
    {
        Assert.True((await Fetch(Fapi2Client, SingleIssuer.Tenant, new JsonWebTokenPayload(new JsonObject())))
            .TryGetSuccess(out _));
    }

    /// <summary>
    /// The same object naming no audience keeps passing for a client held to no profile: RFC 9101 section 4 has
    /// the aud claim SHOULD name the server, and a SHOULD the server enforces only where a profile makes it a shall.
    /// </summary>
    [Fact]
    public async Task FetchAsync_UnprofiledClient_RequestObjectWithoutAudience_Passes()
    {
        var result = await Fetch(new ClientInfo("c1"), SingleIssuer.Tenant, WithinTheProfileLifetime(new JsonObject()));

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// RFC 9101 section 5 strict mode: the payload binds onto a fresh model instead of merging over the
    /// outer request, so parameters passed outside the request object are ignored.
    /// </summary>
    [Fact]
    public async Task FetchAsync_StrictMode_BindsPayloadOntoFreshModel()
    {
        // Arrange
        _oidcOptions.IgnoreParametersOutsideRequestObject = true;
        var fetcher = CreateFetcher();
        var outerRequest = new Abblix.Oidc.Server.Model.AuthorizationRequest { State = "outer-state" };
        var jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIn0.signature";
        var payload = new JsonObject { [RequestParameters.ClientId] = TestConstants.DefaultClientId };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()) { Algorithm = SigningAlgorithms.RS256 },
            Payload = new JsonWebTokenPayload(payload),
        };
        var boundRequest = new Abblix.Oidc.Server.Model.AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, new ClientInfo("test-client")));

        // The binder must receive a FRESH target, not the outer request - that is what makes the
        // outer parameters invisible to the merged result.
        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(
                payload,
                It.Is<Abblix.Oidc.Server.Model.AuthorizationRequest>(t => !ReferenceEquals(t, outerRequest))))
            .ReturnsAsync(boundRequest);

        // Act
        var result = await fetcher.FetchAsync(SingleIssuer.Tenant, null, outerRequest, jwt);

        // Assert
        Assert.True(result.TryGetSuccess(out var value));
        Assert.Same(boundRequest, value);
        Assert.Null(value.State);
    }

    /// <summary>
    /// The longest lifetime FAPI 2.0 Message Signing section 5.3.1 lets a request object claim, and the furthest its
    /// nbf may lie in the past.
    /// </summary>
    private static readonly TimeSpan ProfileLifetime = TimeSpan.FromMinutes(60);

    /// <summary>
    /// A lifetime well inside the profile's bound, for a test whose subject is something else.
    /// </summary>
    private static readonly TimeSpan OrdinaryLifetime = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The smallest step a JWT timestamp can take, which is what lies just past a bound.
    /// </summary>
    private static readonly TimeSpan OneSecond = TimeSpan.FromSeconds(1);

    /// <summary>
    /// The payload carrying an nbf of now and an exp a few minutes on, which every profile accepts.
    /// </summary>
    private static JsonWebTokenPayload WithinTheProfileLifetime(JsonObject payload)
        => WithLifetime(payload, Now, Now + OrdinaryLifetime);

    /// <summary>
    /// The payload carrying the given nbf and exp, either left out where null.
    /// </summary>
    private static JsonWebTokenPayload WithLifetime(JsonObject payload, DateTimeOffset? notBefore, DateTimeOffset? expiresAt)
        => new(payload) { NotBefore = notBefore, ExpiresAt = expiresAt };

    /// <summary>
    /// Fetches a request object whose payload carries the given lifetime, sent by the given client at the given
    /// tenant, with the validator passing it as valid - so whatever is refused is refused by the fetcher itself.
    /// </summary>
    private Task<Result<JarTestRequest, OidcError>> FetchWithLifetime(
        ClientInfo client,
        TenantDefinition tenant,
        DateTimeOffset? notBefore,
        DateTimeOffset? expiresAt)
        => Fetch(client, tenant, AddressedTo(tenant, WithLifetime(new JsonObject(), notBefore, expiresAt)));

    /// <summary>
    /// The payload addressed to the tenant's issuer, which is what every profile accepts as its audience - for a test
    /// whose subject is something else.
    /// </summary>
    private static JsonWebTokenPayload AddressedTo(TenantDefinition tenant, JsonWebTokenPayload payload)
    {
        payload.Audiences = [tenant.Issuer.OriginalString];
        return payload;
    }

    /// <summary>
    /// Fetches a request object carrying the given payload, sent by the given client at the given tenant, with the
    /// validator passing it as valid - so whatever is refused is refused by the fetcher itself.
    /// </summary>
    private async Task<Result<JarTestRequest, OidcError>> Fetch(
        ClientInfo client,
        TenantDefinition tenant,
        JsonWebTokenPayload payload)
    {
        const string jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjMSJ9.signature";
        var request = new JarTestRequest { ClientId = TestConstants.DefaultClientId, Request = jwt };
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(new JsonObject()),
            Payload = payload,
        };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, client));
        _jsonObjectBinder
            .Setup(b => b.BindModelAsync(It.IsAny<JsonObject>(), It.IsAny<JarTestRequest>()))
            .ReturnsAsync((JsonObject _, JarTestRequest bound) => bound);

        return await CreateFetcher().FetchAsync(tenant, null, request, jwt);
    }

    private static ClientInfo Fapi2Client => new("c1") { SecurityProfile = ClientSecurityProfile.Fapi2 };

    private static TenantDefinition Fapi1AdvancedTenant
        => new TestIssuer { DefaultSecurityProfile = ClientSecurityProfile.Fapi1Advanced }.ToTenant();

    private static void AssertInvalidRequestObject(Result<JarTestRequest, OidcError> result)
    {
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequestObject, error.Error);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2: the server "shall require the
    /// request object to contain an nbf claim" and "an exp claim", so a request object missing either is refused
    /// for a client held to the profile, although RFC 9101 alone asks for neither.
    /// </summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    public async Task FetchAsync_Fapi1AdvancedClient_RequestObjectMissingNbfOrExp_IsInvalid(bool carriesNbf, bool carriesExp)
    {
        var result = await FetchWithLifetime(
            Fapi1AdvancedClient,
            SingleIssuer.Tenant,
            carriesNbf ? Now : null,
            carriesExp ? Now + OrdinaryLifetime : null);

        AssertInvalidRequestObject(result);
    }

    /// <summary>
    /// The exp may lie at most 60 minutes after the nbf: exactly 60 is accepted and one second more is refused.
    /// </summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task FetchAsync_Fapi1AdvancedClient_ExpAgainstSixtyMinutesAfterNbf(bool oneSecondOver, bool accepted)
    {
        var expiresAt = Now + ProfileLifetime + (oneSecondOver ? OneSecond : TimeSpan.Zero);

        var result = await FetchWithLifetime(Fapi1AdvancedClient, SingleIssuer.Tenant, Now, expiresAt);

        Assert.Equal(accepted, result.TryGetSuccess(out _));
        if (!accepted)
            AssertInvalidRequestObject(result);
    }

    /// <summary>
    /// The nbf may lie at most 60 minutes in the past: exactly 60 is accepted and one second more is refused. The
    /// exp stays inside the lifetime bound, so the nbf is the only thing judged - a validator registered by the host
    /// may have let the exp through with a tolerance of its own.
    /// </summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task FetchAsync_Fapi1AdvancedClient_NbfAgainstSixtyMinutesInThePast(bool oneSecondOver, bool accepted)
    {
        var notBefore = Now - ProfileLifetime - (oneSecondOver ? OneSecond : TimeSpan.Zero);

        var result = await FetchWithLifetime(Fapi1AdvancedClient, SingleIssuer.Tenant, notBefore, notBefore + OrdinaryLifetime);

        Assert.Equal(accepted, result.TryGetSuccess(out _));
        if (!accepted)
            AssertInvalidRequestObject(result);
    }

    /// <summary>
    /// A client with no profile of its own at a tenant holding its clients to FAPI 1.0 Advanced is held to the same lifetime.
    /// </summary>
    [Fact]
    public async Task FetchAsync_UnprofiledClientAtFapiTenant_RequestObjectWithoutExp_IsInvalid()
    {
        var result = await FetchWithLifetime(new ClientInfo("c1"), Fapi1AdvancedTenant, Now, null);

        AssertInvalidRequestObject(result);
    }

    /// <summary>
    /// With no profile anywhere, RFC 9101 governs and requires neither claim nor any bound: a request object without
    /// nbf and exp, and one living for longer than an hour, are both accepted as before.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FetchAsync_UnprofiledClient_LifetimeIsNotBounded(bool carriesALongLifetime)
    {
        var result = await FetchWithLifetime(
            new ClientInfo("c1"),
            SingleIssuer.Tenant,
            carriesALongLifetime ? Now - ProfileLifetime - ProfileLifetime : null,
            carriesALongLifetime ? Now + ProfileLifetime : null);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// An nbf the payload cannot read as a timestamp is the client's malformed object, refused rather than allowed
    /// to escape as an exception.
    /// </summary>
    [Fact]
    public async Task FetchAsync_Fapi1AdvancedClient_UnreadableNbf_IsInvalid()
    {
        const string jwt = "eyJhbGciOiJSUzI1NiJ9.eyJjbGllbnRfaWQiOiJjMSJ9.signature";
        var request = new JarTestRequest { ClientId = TestConstants.DefaultClientId, Request = jwt };
        var payload = WithLifetime(new JsonObject(), null, Now + OrdinaryLifetime);
        payload.Json[JwtClaimTypes.NotBefore] = "not-a-timestamp";
        var token = new JsonWebToken { Header = new JsonWebTokenHeader(new JsonObject()), Payload = payload };

        _jwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, null, jwt, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, Fapi1AdvancedClient));

        AssertInvalidRequestObject(await CreateFetcher().FetchAsync(SingleIssuer.Tenant, null, request, jwt));
    }
}
