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

using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// Unit tests for <see cref="ScopeValidator"/> verifying scope validation
/// for token requests per OAuth 2.0 specification.
/// </summary>
public class ScopeValidatorTests
{
    private readonly Mock<IScopeManager> _scopeManager;
    private readonly ScopeValidator _validator;

    public ScopeValidatorTests()
    {
        _scopeManager = new Mock<IScopeManager>(MockBehavior.Strict);
        _validator = new ScopeValidator(_scopeManager.Object);
    }

    private static TokenValidationContext CreateContext(
        string[] scope,
        ResourceDefinition[]? resources = null)
    {
        var tokenRequest = new TokenRequest
        {
            Scope = scope,
        };
        var clientRequest = new ClientRequest();
        var context = new TokenValidationContext(tokenRequest, clientRequest);
        if (resources != null)
        {
            context.Resources = resources;
        }
        return context;
    }

    /// <summary>
    /// Helper to setup TryGet mock for a collection of scopes.
    /// </summary>
    private void SetupScopeManagerForScopes(params string[] scopes)
    {
        foreach (var scope in scopes)
        {
            var scopeDef = new ScopeDefinition(scope);
            _scopeManager
                .Setup(m => m.TryGet(scope, out It.Ref<ScopeDefinition>.IsAny))
                .Returns(new ScopeManagerTryGetCallback((string s, out ScopeDefinition def) =>
                {
                    def = scopeDef;
                    return true;
                }));
        }
    }

    private delegate bool ScopeManagerTryGetCallback(
        string scope,
        [MaybeNullWhen(false)] out ScopeDefinition definition);

    /// <summary>
    /// Verifies successful validation with valid scopes.
    /// Per OAuth 2.0, scopes must be validated against scope manager.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidScopes_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(scope: ["read", "write"]);
        SetupScopeManagerForScopes("read", "write");

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Equal(2, context.Scope.Length);
        Assert.Contains(context.Scope, s => s.Scope == "read");
        Assert.Contains(context.Scope, s => s.Scope == "write");
    }

    /// <summary>
    /// Verifies error when scope validation fails.
    /// Per OAuth 2.0, invalid scopes must be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenScopeValidationFails_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(scope: ["invalid_scope"]);

        // Don't setup TryGet for "invalid_scope", so it returns false by default
        _scopeManager
            .Setup(m => m.TryGet("invalid_scope", out It.Ref<ScopeDefinition>.IsAny))
            .Returns(false);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidScope, error.Error);
        Assert.Contains("not available", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies scope manager receives correct scope requests via TryGet.
    /// Manager should be called for each scope in the context.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPassCorrectParametersToScopeManager()
    {
        // Arrange
        var scopes = new[] { "openid", "profile", "email" };
        var context = CreateContext(scope: scopes);
        SetupScopeManagerForScopes("openid", "profile", "email");

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _scopeManager.Verify(m => m.TryGet("openid", out It.Ref<ScopeDefinition>.IsAny), Times.Once);
        _scopeManager.Verify(m => m.TryGet("profile", out It.Ref<ScopeDefinition>.IsAny), Times.Once);
        _scopeManager.Verify(m => m.TryGet("email", out It.Ref<ScopeDefinition>.IsAny), Times.Once);
    }

    /// <summary>
    /// Verifies context.Scope is set correctly on success.
    /// Validated scope definitions should be assigned to context.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetScopeInContext()
    {
        // Arrange
        var context = CreateContext(scope: ["openid", "profile"]);
        SetupScopeManagerForScopes("openid", "profile");

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Equal(2, context.Scope.Length);
        Assert.Contains(context.Scope, s => s.Scope == "openid");
        Assert.Contains(context.Scope, s => s.Scope == "profile");
    }

    /// <summary>
    /// Verifies error description is generated when scope is not available.
    /// Extension method generates "The scope is not available" message.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPropagateErrorDescription()
    {
        // Arrange
        var context = CreateContext(scope: ["admin"]);

        _scopeManager
            .Setup(m => m.TryGet("admin", out It.Ref<ScopeDefinition>.IsAny))
            .Returns(false);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Contains("not available", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation with empty resources array.
    /// Scopes should still be validated via scope manager.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyResources_ShouldWork()
    {
        // Arrange
        var context = CreateContext(scope: ["read"], resources: []);
        SetupScopeManagerForScopes("read");

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Single(context.Scope);
        Assert.Equal("read", context.Scope[0].Scope);
    }

    /// <summary>
    /// Verifies validation with multiple scopes.
    /// Validator should handle multiple scope values.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleScopes_ShouldValidateAll()
    {
        // Arrange
        var scopes = new[] { "openid", "profile", "email", "address", "phone" };
        var context = CreateContext(scope: scopes);
        SetupScopeManagerForScopes(scopes);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Equal(5, context.Scope.Length);
        foreach (var scopeName in scopes)
        {
            Assert.Contains(context.Scope, s => s.Scope == scopeName);
        }
    }

    /// <summary>
    /// Verifies validation with empty scope array.
    /// Per OAuth 2.0, TokenRequest.Scope defaults to empty array, not null.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullScope_ShouldWork()
    {
        // Arrange
        var context = CreateContext(scope: []);
        // No need to setup scope manager for empty scopes

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Empty(context.Scope);
    }

    /// <summary>
    /// Verifies scope manager TryGet is called once per scope.
    /// Each scope should be looked up exactly once.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallScopeManagerOnce()
    {
        // Arrange
        var context = CreateContext(scope: ["read"]);
        SetupScopeManagerForScopes("read");

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _scopeManager.Verify(
            m => m.TryGet("read", out It.Ref<ScopeDefinition>.IsAny),
            Times.Once);
    }
}
