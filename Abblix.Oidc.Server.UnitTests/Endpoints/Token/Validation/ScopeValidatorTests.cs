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

    private delegate bool ScopeManagerValidateCallback(
        string[]? scopes,
        ResourceDefinition[] resources,
        [MaybeNullWhen(false)] out ScopeDefinition[] scopeDefinitions,
        [MaybeNullWhen(true)] out string? errorDescription);

    private static TokenValidationContext CreateContext(
        string[]? scope = null,
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
    /// Verifies successful validation with valid scopes.
    /// Per OAuth 2.0, scopes must be validated against scope manager.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidScopes_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(scope: ["read", "write"]);
        var scopeDefinitions = new[]
        {
            new ScopeDefinition("read"),
            new ScopeDefinition("write"),
        };

        _scopeManager
            .Setup(m => m.Validate(
                It.IsAny<string[]?>(),
                It.IsAny<ResourceDefinition[]>(),
                out It.Ref<ScopeDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ScopeManagerValidateCallback((string[]? scopes, ResourceDefinition[] resources, out ScopeDefinition[] defs, out string? error) =>
            {
                defs = scopeDefinitions;
                error = null;
                return true;
            }))
            .Returns(true);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Equal(scopeDefinitions, context.Scope);
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

        _scopeManager
            .Setup(m => m.Validate(
                It.IsAny<string[]?>(),
                It.IsAny<ResourceDefinition[]>(),
                out It.Ref<ScopeDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ScopeManagerValidateCallback((string[]? scopes, ResourceDefinition[] resources, out ScopeDefinition[] defs, out string? error) =>
            {
                defs = null!;
                error = "Invalid scope requested";
                return false;
            }))
            .Returns(false);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidScope, error.Error);
        Assert.Contains("Invalid scope requested", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies scope manager receives correct parameters.
    /// Manager should receive scopes and resources from context.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPassCorrectParametersToScopeManager()
    {
        // Arrange
        var scopes = new[] { "openid", "profile", "email" };
        var resources = new[] { new ResourceDefinition(new System.Uri("https://api.example.com")) };
        var context = CreateContext(scope: scopes, resources: resources);
        var scopeDefinitions = new[] { new ScopeDefinition("openid") };

        string[]? capturedScopes = null;
        ResourceDefinition[]? capturedResources = null;

        _scopeManager
            .Setup(m => m.Validate(
                It.IsAny<string[]?>(),
                It.IsAny<ResourceDefinition[]>(),
                out It.Ref<ScopeDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ScopeManagerValidateCallback((string[]? scp, ResourceDefinition[] res, out ScopeDefinition[] defs, out string? error) =>
            {
                capturedScopes = scp;
                capturedResources = res;
                defs = scopeDefinitions;
                error = null;
                return true;
            }))
            .Returns(true);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Equal(scopes, capturedScopes);
        Assert.Same(resources, capturedResources);
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
        var scopeDefinitions = new[]
        {
            new ScopeDefinition("openid"),
            new ScopeDefinition("profile"),
        };

        _scopeManager
            .Setup(m => m.Validate(
                It.IsAny<string[]?>(),
                It.IsAny<ResourceDefinition[]>(),
                out It.Ref<ScopeDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ScopeManagerValidateCallback((string[]? scopes, ResourceDefinition[] resources, out ScopeDefinition[] defs, out string? error) =>
            {
                defs = scopeDefinitions;
                error = null;
                return true;
            }))
            .Returns(true);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Equal(scopeDefinitions, context.Scope);
        Assert.Equal(2, context.Scope.Length);
    }

    /// <summary>
    /// Verifies error description is propagated from scope manager.
    /// Scope manager error messages should be included in response.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPropagateErrorDescription()
    {
        // Arrange
        var context = CreateContext(scope: ["admin"]);
        var errorMessage = "Scope 'admin' is not allowed for this client";

        _scopeManager
            .Setup(m => m.Validate(
                It.IsAny<string[]?>(),
                It.IsAny<ResourceDefinition[]>(),
                out It.Ref<ScopeDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ScopeManagerValidateCallback((string[]? scopes, ResourceDefinition[] resources, out ScopeDefinition[] defs, out string? error) =>
            {
                defs = null!;
                error = errorMessage;
                return false;
            }))
            .Returns(false);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(errorMessage, error.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation with empty resources array.
    /// Validator should pass empty resources to scope manager.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyResources_ShouldWork()
    {
        // Arrange
        var context = CreateContext(scope: ["read"], resources: []);
        var scopeDefinitions = new[] { new ScopeDefinition("read") };

        _scopeManager
            .Setup(m => m.Validate(
                It.IsAny<string[]?>(),
                It.IsAny<ResourceDefinition[]>(),
                out It.Ref<ScopeDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ScopeManagerValidateCallback((string[]? scopes, ResourceDefinition[] resources, out ScopeDefinition[] defs, out string? error) =>
            {
                defs = scopeDefinitions;
                error = null;
                return true;
            }))
            .Returns(true);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
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
        var scopeDefinitions = scopes.Select(s => new ScopeDefinition(s)).ToArray();

        _scopeManager
            .Setup(m => m.Validate(
                It.IsAny<string[]?>(),
                It.IsAny<ResourceDefinition[]>(),
                out It.Ref<ScopeDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ScopeManagerValidateCallback((string[]? scp, ResourceDefinition[] resources, out ScopeDefinition[] defs, out string? error) =>
            {
                defs = scopeDefinitions;
                error = null;
                return true;
            }))
            .Returns(true);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Equal(5, context.Scope.Length);
    }

    /// <summary>
    /// Verifies validation with null scope.
    /// Null scope should be passed to scope manager.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullScope_ShouldWork()
    {
        // Arrange
        var context = CreateContext(scope: null);
        var scopeDefinitions = System.Array.Empty<ScopeDefinition>();

        _scopeManager
            .Setup(m => m.Validate(
                It.IsAny<string[]?>(),
                It.IsAny<ResourceDefinition[]>(),
                out It.Ref<ScopeDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ScopeManagerValidateCallback((string[]? scopes, ResourceDefinition[] resources, out ScopeDefinition[] defs, out string? error) =>
            {
                defs = scopeDefinitions;
                error = null;
                return true;
            }))
            .Returns(true);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies scope manager is called once per validation.
    /// Multiple calls to the same manager should be avoided.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallScopeManagerOnce()
    {
        // Arrange
        var context = CreateContext(scope: ["read"]);
        var scopeDefinitions = new[] { new ScopeDefinition("read") };

        _scopeManager
            .Setup(m => m.Validate(
                It.IsAny<string[]?>(),
                It.IsAny<ResourceDefinition[]>(),
                out It.Ref<ScopeDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ScopeManagerValidateCallback((string[]? scopes, ResourceDefinition[] resources, out ScopeDefinition[] defs, out string? error) =>
            {
                defs = scopeDefinitions;
                error = null;
                return true;
            }))
            .Returns(true);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _scopeManager.Verify(
            m => m.Validate(
                It.IsAny<string[]?>(),
                It.IsAny<ResourceDefinition[]>(),
                out It.Ref<ScopeDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny),
            Times.Once);
    }
}
