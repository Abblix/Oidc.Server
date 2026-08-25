// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Endpoints.Introspection;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Introspection;

/// <summary>
/// Unit tests for <see cref="IntrospectionRequestProcessor"/> verifying introspection logic
/// per RFC 7662 Token Introspection specification.
/// </summary>
public class IntrospectionRequestProcessorTests
{
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly Mock<ISubjectTypeConverter> _subjectTypeConverter;
    private readonly IntrospectionRequestProcessor _processor;

    public IntrospectionRequestProcessorTests()
    {
        // Neither is reached for a caller that is the token's own client, nor for one that is not pairwise,
        // which is every case here except the pseudonym one below.
        _clientInfoProvider = new Mock<IClientInfoProvider>();
        _subjectTypeConverter = new Mock<ISubjectTypeConverter>();

        _processor = new IntrospectionRequestProcessor(
            _clientInfoProvider.Object,
            _subjectTypeConverter.Object);
    }

    private static IntrospectionRequest CreateIntrospectionRequest() => new()
    {
        Token = "access_token_value",
        TokenTypeHint = "access_token",
    };

    private static JsonWebToken CreateValidToken()
    {
        var token = new JsonWebToken();
        token.Payload.Json["sub"] = "user_123";
        token.Payload.Json[IanaClaimTypes.ClientId] = "client_456";
        token.Payload.Json[IanaClaimTypes.Scope] = "openid profile";
        return token;
    }

    /// <summary>
    /// The caller defaults to the client the token was issued to, because that is the pairing these cases are
    /// about: what the token's own client receives. A caller that differs is the protected-resource path of
    /// RFC 7662, and it is answered with a narrowed response - pass <paramref name="callerClientId"/> to reach
    /// it deliberately rather than through a fixture that happened to name two different clients.
    /// </summary>
    private static ValidIntrospectionRequest CreateValidIntrospectionRequest(
        IntrospectionRequest request,
        JsonWebToken? token = null,
        string? callerClientId = null,
        Uri[]? callerResourceLocations = null)
    {
        var clientId = callerClientId ?? token?.Payload.ClientId ?? "test_client";
        var caller = new ClientInfo(clientId) { ResourceLocations = callerResourceLocations };
        return new ValidIntrospectionRequest(request, caller, token!);
    }

    /// <summary>
    /// Verifies introspection with valid token returns active: true.
    /// Per RFC 7662 Section 2.2, active tokens return active field set to true.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithValidToken_ShouldReturnActiveTrue()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        var validRequest = CreateValidIntrospectionRequest(request, token);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.True(success.Active);
    }

    /// <summary>
    /// Verifies introspection with valid token returns claims from payload.
    /// Tests that token claims are included in introspection response.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithValidToken_ShouldReturnClaims()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        var validRequest = CreateValidIntrospectionRequest(request, token);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.NotNull(success.Claims);
        Assert.Equal("user_123", success.Claims["sub"]?.GetValue<string>());
        Assert.Equal("client_456", success.Claims[IanaClaimTypes.ClientId]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies introspection with null token returns active: false.
    /// Per RFC 7662 Section 2.2, inactive tokens return active field set to false.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithNullToken_ShouldReturnActiveFalse()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var validRequest = CreateValidIntrospectionRequest(request);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.False(success.Active);
    }

    /// <summary>
    /// Verifies introspection with null token returns no claims.
    /// Per RFC 7662 Section 2.2, inactive tokens should not include additional information.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithNullToken_ShouldReturnNullClaims()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var validRequest = CreateValidIntrospectionRequest(request);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.Null(success.Claims);
    }

    /// <summary>
    /// Verifies introspection always succeeds.
    /// Tests that processor never returns error result.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldAlwaysSucceed()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        var validRequest = CreateValidIntrospectionRequest(request, token);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies introspection echoes the token payload directly, so a pairwise client sees its own opaque per-sector
    /// pseudonym in <c>sub</c> - which is meaningful only to the issuing server and leaks nothing extra.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldEchoPayloadClaims()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        var validRequest = CreateValidIntrospectionRequest(request, token);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.Same(token.Payload.Json, success.Claims);
        Assert.Equal("user_123", success.Claims?["sub"]?.GetValue<string>());
    }

    /// <summary>
    /// A caller the token was not issued to is answered without the end-user identifier, and without any claim
    /// beyond the members RFC 7662 Section 2.2 defines. Section 5: "measures MUST be taken to prevent
    /// disclosure of this information to unintended parties", and "omitting privacy-sensitive information from
    /// an introspection response is the simplest way of minimizing privacy issues".
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ForAnotherClientsToken_ShouldWithholdTheSubjectAndUnlistedClaims()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        token.Payload.Json["department"] = "finance";
        var validRequest = CreateValidIntrospectionRequest(request, token, callerClientId: "resource_server");

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.NotNull(success.Claims);
        Assert.False(success.Claims!.ContainsKey(IanaClaimTypes.Sub));
        Assert.False(success.Claims.ContainsKey("department"));

        // The caller still gets what it came for: who the token is for and what it may do.
        Assert.Equal("client_456", success.Claims[IanaClaimTypes.ClientId]?.GetValue<string>());
        Assert.Equal("openid profile", success.Claims[IanaClaimTypes.Scope]?.GetValue<string>());
    }

    /// <summary>
    /// RFC 9396 §9 makes the granted authorization_details reaching the resource server a MUST, by the
    /// access token or by introspection. A deployment encrypting its access tokens to its own keys has
    /// only the second, and the caller names itself through the locations it answers for (§2.2), which
    /// is the filter §9.2 sanctions.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ForAResourceServerNamedInLocations_ReturnsItsOwnEntries()
    {
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        token.Payload.Json[IanaClaimTypes.AuthorizationDetails] = new JsonArray(
            new JsonObject
            {
                ["type"] = "payment_initiation",
                ["locations"] = new JsonArray("https://payments.example.com"),
            },
            new JsonObject
            {
                ["type"] = "account_information",
                ["locations"] = new JsonArray("https://accounts.example.com"),
            },
            new JsonObject { ["type"] = "addressed_to_nobody" });

        var validRequest = CreateValidIntrospectionRequest(
            request,
            token,
            callerClientId: "payments_resource_server",
            callerResourceLocations: [new Uri("https://payments.example.com")]);

        var result = await _processor.ProcessAsync(validRequest);

        Assert.True(result.TryGetSuccess(out var success));
        var details = Assert.IsType<JsonArray>(success.Claims![IanaClaimTypes.AuthorizationDetails]);

        // Its own entry, and only that one: the other resource server's is not its business, and an
        // entry naming no location is addressed to nobody in particular.
        var entry = Assert.Single(details);
        Assert.Equal("payment_initiation", entry!["type"]!.GetValue<string>());
    }

    [Fact]
    public async Task ProcessAsync_ForACallerThatNamesNoLocations_WithholdsTheDetails()
    {
        // The disclosure is opt-in per client, so a deployment that has not named any resource server
        // answers exactly as it did before this existed.
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        token.Payload.Json[IanaClaimTypes.AuthorizationDetails] = new JsonArray(
            new JsonObject
            {
                ["type"] = "payment_initiation",
                ["locations"] = new JsonArray("https://payments.example.com"),
            });

        var validRequest = CreateValidIntrospectionRequest(
            request, token, callerClientId: "payments_resource_server");

        var result = await _processor.ProcessAsync(validRequest);

        Assert.True(result.TryGetSuccess(out var success));
        Assert.False(success.Claims!.ContainsKey(IanaClaimTypes.AuthorizationDetails));
    }

    /// <summary>
    /// RFC 9396 §12: "No additional transformation or normalization is to be done in evaluating
    /// equivalence of string values". Every input here is one that a parsed comparison would have called
    /// equal, and each of them opens one resource server's entry to another - the dot-segment case joins
    /// two resource servers separated only by a path, which is the ordinary deployment shape.
    /// </summary>
    [Theory]
    [InlineData("https://api.example.com/accounts/../payments")]
    [InlineData("https://api.example.com/pa%79ments")]
    [InlineData("HTTPS://API.EXAMPLE.COM/PAYMENTS")]
    [InlineData("https://api.example.com:443/payments")]
    [InlineData("https://api.example.com/payments/")]
    [InlineData("https://api.example.com/payments#fragment")]
    [InlineData("https://someone@api.example.com/payments")]
    [InlineData("  https://api.example.com/payments  ")]
    public async Task ProcessAsync_ForALocationThatOnlyMatchesAfterNormalisation_WithholdsTheDetails(
        string location)
    {
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        token.Payload.Json[IanaClaimTypes.AuthorizationDetails] = new JsonArray(
            new JsonObject
            {
                ["type"] = "payment_initiation",
                ["locations"] = new JsonArray(location),
            });

        var validRequest = CreateValidIntrospectionRequest(
            request,
            token,
            callerClientId: "payments_resource_server",
            callerResourceLocations: [new Uri("https://api.example.com/payments")]);

        var result = await _processor.ProcessAsync(validRequest);

        Assert.True(result.TryGetSuccess(out var success));
        Assert.False(success.Claims!.ContainsKey(IanaClaimTypes.AuthorizationDetails));
    }

    [Fact]
    public async Task ProcessAsync_ForAnEntryNamingSeveralLocations_DisclosesOnlyTheCallersOwn()
    {
        // RFC 7662 §2.2 grants the latitude to answer resources differently "to prevent a protected
        // resource from learning more about the larger network than is necessary for its operation", and
        // §9.2 of RFC 9396 allows the member to be filtered for the caller. An entry naming three
        // addresses would otherwise hand each of them the other two.
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        token.Payload.Json[IanaClaimTypes.AuthorizationDetails] = new JsonArray(
            new JsonObject
            {
                ["type"] = "payment_initiation",
                ["locations"] = new JsonArray(
                    "https://payments.example.com",
                    "https://internal-ledger.corp.example/private"),
            });

        var validRequest = CreateValidIntrospectionRequest(
            request,
            token,
            callerClientId: "payments_resource_server",
            callerResourceLocations: [new Uri("https://payments.example.com")]);

        var result = await _processor.ProcessAsync(validRequest);

        Assert.True(result.TryGetSuccess(out var success));
        var details = Assert.IsType<JsonArray>(success.Claims![IanaClaimTypes.AuthorizationDetails]);
        var locations = Assert.IsType<JsonArray>(Assert.Single(details)!["locations"]);

        Assert.Equal("https://payments.example.com", Assert.Single(locations)!.GetValue<string>());
    }

    [Fact]
    public async Task ProcessAsync_ForACallerOnTheSameHostButAnotherPath_WithholdsTheDetails()
    {
        // Two resource servers behind one host is the ordinary shape, and a comparison that stopped at
        // the host would hand each of them the other's entries.
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        token.Payload.Json[IanaClaimTypes.AuthorizationDetails] = new JsonArray(
            new JsonObject
            {
                ["type"] = "payment_initiation",
                ["locations"] = new JsonArray("https://api.example.com/payments"),
            });

        var validRequest = CreateValidIntrospectionRequest(
            request,
            token,
            callerClientId: "accounts_resource_server",
            callerResourceLocations: [new Uri("https://api.example.com/accounts")]);

        var result = await _processor.ProcessAsync(validRequest);

        Assert.True(result.TryGetSuccess(out var success));
        Assert.False(success.Claims!.ContainsKey(IanaClaimTypes.AuthorizationDetails));
    }

    [Fact]
    public async Task ProcessAsync_ForTheTokensOwnClient_ReturnsTheDetailsWithoutAnyFilter()
    {
        // The token's own client receives its payload as it stands, which is what it already holds.
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        token.Payload.Json[IanaClaimTypes.AuthorizationDetails] = new JsonArray(
            new JsonObject { ["type"] = "payment_initiation" });

        var validRequest = CreateValidIntrospectionRequest(request, token);

        var result = await _processor.ProcessAsync(validRequest);

        Assert.True(result.TryGetSuccess(out var success));
        var details = Assert.IsType<JsonArray>(success.Claims![IanaClaimTypes.AuthorizationDetails]);
        Assert.Single(details);
    }

    /// <summary>
    /// Verifies introspection preserves all claims from token payload.
    /// Tests that all token claims are included in response.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldPreserveAllClaims()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var token = new JsonWebToken();
        token.Payload.Json["sub"] = "user_123";
        token.Payload.Json[IanaClaimTypes.ClientId] = "client_456";
        token.Payload.Json[IanaClaimTypes.Scope] = "openid profile email";
        token.Payload.Json["custom_claim"] = "custom_value";
        token.Payload.Json["aud"] = new JsonArray { "audience1", "audience2" };
        var validRequest = CreateValidIntrospectionRequest(request, token);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.NotNull(success.Claims);
        Assert.Equal(5, success.Claims.Count);
        Assert.Equal("user_123", success.Claims["sub"]?.GetValue<string>());
        Assert.Equal("client_456", success.Claims[IanaClaimTypes.ClientId]?.GetValue<string>());
        Assert.Equal("openid profile email", success.Claims[IanaClaimTypes.Scope]?.GetValue<string>());
        Assert.Equal("custom_value", success.Claims["custom_claim"]?.GetValue<string>());
        Assert.Equal(2, success.Claims["aud"]?.AsArray().Count);
    }

    /// <summary>
    /// Verifies introspection with different tokens returns different claims.
    /// Tests that each token's claims are returned independently.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithDifferentTokens_ShouldReturnDifferentClaims()
    {
        // Arrange
        // Both tokens carry client_id as every minted access token does, and each is introspected by its own
        // client, so the responses are the full ones.
        var request1 = CreateIntrospectionRequest();
        var token1 = new JsonWebToken();
        token1.Payload.Json["sub"] = "user_1";
        token1.Payload.Json[IanaClaimTypes.ClientId] = "client_456";
        var validRequest1 = CreateValidIntrospectionRequest(request1, token1);

        var request2 = CreateIntrospectionRequest();
        var token2 = new JsonWebToken();
        token2.Payload.Json["sub"] = "user_2";
        token2.Payload.Json[IanaClaimTypes.ClientId] = "client_456";
        var validRequest2 = CreateValidIntrospectionRequest(request2, token2);

        // Act
        var result1 = await _processor.ProcessAsync(validRequest1);
        var result2 = await _processor.ProcessAsync(validRequest2);

        // Assert
        Assert.True(result1.TryGetSuccess(out var success1));
        Assert.True(result2.TryGetSuccess(out var success2));
        Assert.Equal("user_1", success1.Claims?["sub"]?.GetValue<string>());
        Assert.Equal("user_2", success2.Claims?["sub"]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies introspection with empty token payload returns active: true with empty claims.
    /// Tests handling of valid but empty token.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithEmptyTokenPayload_ShouldReturnActiveTrueWithEmptyClaims()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var token = new JsonWebToken(); // Empty payload
        var validRequest = CreateValidIntrospectionRequest(request, token);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.True(success.Active);
        Assert.NotNull(success.Claims);
        Assert.Empty(success.Claims);
    }

    /// <summary>
    /// Verifies introspection returns IntrospectionSuccess with correct structure.
    /// Tests that response type is correct.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldReturnIntrospectionSuccess()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var token = CreateValidToken();
        var validRequest = CreateValidIntrospectionRequest(request, token);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.IsType<IntrospectionSuccess>(success);
    }

    /// <summary>
    /// Verifies introspection handles complex claim structures.
    /// Tests that nested objects and arrays are preserved.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithComplexClaims_ShouldPreserveStructure()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var token = new JsonWebToken();
        token.Payload.Json["sub"] = "user_123";
        // Every access token this server mints carries client_id, and the caller here is that same client -
        // this case is about the full response its own client receives.
        token.Payload.Json[IanaClaimTypes.ClientId] = "client_456";
        token.Payload.Json["address"] = new JsonObject
        {
            ["street"] = "123 Main St",
            ["city"] = "New York",
            ["country"] = "USA"
        };
        token.Payload.Json["roles"] = new JsonArray { "admin", "user", "viewer" };
        var validRequest = CreateValidIntrospectionRequest(request, token);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var success));
        Assert.NotNull(success.Claims);
        var address = success.Claims["address"]?.AsObject();
        Assert.NotNull(address);
        Assert.Equal("123 Main St", address["street"]?.GetValue<string>());
        Assert.Equal("New York", address["city"]?.GetValue<string>());
        Assert.Equal("USA", address["country"]?.GetValue<string>());
        var roles = success.Claims["roles"]?.AsArray();
        Assert.NotNull(roles);
        Assert.Equal(3, roles.Count);
        Assert.Equal("admin", roles[0]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies introspection never returns error.
    /// Per design, introspection processor always succeeds.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldNeverReturnError()
    {
        // Arrange
        var request = CreateIntrospectionRequest();
        var validRequest = CreateValidIntrospectionRequest(request);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.False(result.TryGetFailure(out _));
    }
}
