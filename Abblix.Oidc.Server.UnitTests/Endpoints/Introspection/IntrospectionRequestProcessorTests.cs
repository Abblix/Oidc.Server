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

using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Endpoints.Introspection;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Introspection;

/// <summary>
/// Unit tests for <see cref="IntrospectionRequestProcessor"/> verifying introspection logic
/// per RFC 7662 Token Introspection specification.
/// </summary>
public class IntrospectionRequestProcessorTests
{
    private readonly IntrospectionRequestProcessor _processor;

    public IntrospectionRequestProcessorTests()
    {
        _processor = new IntrospectionRequestProcessor();
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
        token.Payload.Json["client_id"] = "client_456";
        token.Payload.Json["scope"] = "openid profile";
        return token;
    }

    private static ValidIntrospectionRequest CreateValidIntrospectionRequest(
        IntrospectionRequest request,
        JsonWebToken? token = null)
    {
        return new ValidIntrospectionRequest(request, token);
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
        Assert.Equal("client_456", success.Claims["client_id"]?.GetValue<string>());
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
        var validRequest = CreateValidIntrospectionRequest(request, null);

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
        var validRequest = CreateValidIntrospectionRequest(request, null);

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
    /// Verifies introspection returns payload JSON directly.
    /// Tests that claims come from token.Payload.Json.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldReturnPayloadJson()
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
        token.Payload.Json["client_id"] = "client_456";
        token.Payload.Json["scope"] = "openid profile email";
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
        Assert.Equal("client_456", success.Claims["client_id"]?.GetValue<string>());
        Assert.Equal("openid profile email", success.Claims["scope"]?.GetValue<string>());
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
        var request1 = CreateIntrospectionRequest();
        var token1 = new JsonWebToken();
        token1.Payload.Json["sub"] = "user_1";
        var validRequest1 = CreateValidIntrospectionRequest(request1, token1);

        var request2 = CreateIntrospectionRequest();
        var token2 = new JsonWebToken();
        token2.Payload.Json["sub"] = "user_2";
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
        var validRequest = CreateValidIntrospectionRequest(request, null);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.False(result.TryGetFailure(out _));
    }
}
