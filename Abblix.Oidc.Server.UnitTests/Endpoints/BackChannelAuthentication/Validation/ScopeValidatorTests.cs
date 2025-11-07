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
using System.Collections;
using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Unit tests for <see cref="ScopeValidator"/> verifying CIBA scope validation
/// per OpenID Connect Core and OAuth 2.0 specifications.
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

    private BackChannelAuthenticationValidationContext CreateContext(
        string[]? scopes = null,
        bool offlineAccessAllowed = false,
        ResourceDefinition[]? resources = null)
    {
        var request = new BackChannelAuthenticationRequest
        {
            Scope = scopes ?? new[] { "openid" }
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        return new BackChannelAuthenticationValidationContext(request, clientRequest)
        {
            ClientInfo = new ClientInfo("test-client")
            {
                OfflineAccessAllowed = offlineAccessAllowed
            },
            Resources = resources
        };
    }

    private delegate bool TryGetCallback(string scope, out ScopeDefinition? definition);

    /// <summary>
    /// Verifies validation succeeds with valid openid scope.
    /// Per OpenID Connect Core, openid scope is mandatory for OIDC requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidOpenIdScope_ShouldReturnNull()
    {
        // Arrange
        var openidDefinition = new ScopeDefinition("openid", Array.Empty<string>());

        _scopeManager
            .Setup(sm => sm.TryGet("openid", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = openidDefinition;
                return true;
            }));

        var context = CreateContext(scopes: new[] { "openid" });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.Scope);
        Assert.Single(context.Scope);
    }

    /// <summary>
    /// Verifies error when offline_access is requested but not allowed.
    /// Per OAuth 2.0, offline_access requires explicit client permission.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithOfflineAccessNotAllowed_ShouldReturnInvalidScope()
    {
        // Arrange
        var context = CreateContext(
            scopes: new[] { "openid", "offline_access" },
            offlineAccessAllowed: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
        Assert.Equal("This client is not allowed to request for offline access", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds when offline_access is requested and allowed.
    /// Client must have OfflineAccessAllowed = true to request refresh tokens.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithOfflineAccessAllowed_ShouldReturnNull()
    {
        // Arrange
        var openidDefinition = new ScopeDefinition("openid", Array.Empty<string>());
        var offlineAccessDefinition = new ScopeDefinition("offline_access", Array.Empty<string>());

        _scopeManager
            .Setup(sm => sm.TryGet("openid", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = openidDefinition;
                return true;
            }));

        _scopeManager
            .Setup(sm => sm.TryGet("offline_access", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = offlineAccessDefinition;
                return true;
            }));

        var context = CreateContext(
            scopes: new[] { "openid", "offline_access" },
            offlineAccessAllowed: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.Scope);
        Assert.Equal(2, context.Scope.Length);
    }

    /// <summary>
    /// Verifies error when scope is unknown to both scope manager and resources.
    /// All requested scopes must be recognized.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnknownScope_ShouldReturnInvalidScope()
    {
        // Arrange
        _scopeManager
            .Setup(sm => sm.TryGet("unknown_scope", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = null;
                return false;
            }));

        var context = CreateContext(scopes: new[] { "unknown_scope" });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
        Assert.Equal("The scope is not available", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with multiple valid scopes.
    /// Multiple scopes are commonly requested in OIDC flows.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleValidScopes_ShouldReturnNull()
    {
        // Arrange
        var openidDef = new ScopeDefinition("openid", Array.Empty<string>());
        var profileDef = new ScopeDefinition("profile", Array.Empty<string>());
        var emailDef = new ScopeDefinition("email", Array.Empty<string>());

        _scopeManager
            .Setup(sm => sm.TryGet("openid", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = openidDef;
                return true;
            }));

        _scopeManager
            .Setup(sm => sm.TryGet("profile", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = profileDef;
                return true;
            }));

        _scopeManager
            .Setup(sm => sm.TryGet("email", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = emailDef;
                return true;
            }));

        var context = CreateContext(scopes: new[] { "openid", "profile", "email" });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.Scope);
        Assert.Equal(3, context.Scope.Length);
    }

    /// <summary>
    /// Verifies scope from resource definition is accepted even if not in scope manager.
    /// Per RFC 8707, resources may define their own scopes.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithScopeFromResource_ShouldReturnNull()
    {
        // Arrange
        var openidDef = new ScopeDefinition("openid", Array.Empty<string>());
        var resourceScopeDef = new ScopeDefinition("api:read", Array.Empty<string>());

        var resourceDefinition = new ResourceDefinition(
            new Uri("https://api.example.com"),
            resourceScopeDef);

        _scopeManager
            .Setup(sm => sm.TryGet("openid", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = openidDef;
                return true;
            }));

        _scopeManager
            .Setup(sm => sm.TryGet("api:read", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = null;
                return false;
            }));

        var context = CreateContext(
            scopes: new[] { "openid", "api:read" },
            resources: new[] { resourceDefinition });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.Scope);
        Assert.Single(context.Scope); // Only openid added to scope list
    }

    /// <summary>
    /// Verifies context.Scope is always set on successful validation.
    /// Downstream handlers depend on this value.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetScopeOnContext()
    {
        // Arrange
        var openidDefinition = new ScopeDefinition("openid", Array.Empty<string>());

        _scopeManager
            .Setup(sm => sm.TryGet("openid", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = openidDefinition;
                return true;
            }));

        var context = CreateContext(scopes: new[] { "openid" });

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(context.Scope);
        Assert.Single(context.Scope);
        Assert.Equal("openid", context.Scope[0].Scope);
    }

    /// <summary>
    /// Verifies validation fails at first unknown scope.
    /// Error should be returned immediately without processing remaining scopes.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMixedScopes_ShouldFailAtFirstUnknown()
    {
        // Arrange
        var openidDef = new ScopeDefinition("openid", Array.Empty<string>());

        _scopeManager
            .Setup(sm => sm.TryGet("openid", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = openidDef;
                return true;
            }));

        _scopeManager
            .Setup(sm => sm.TryGet("unknown", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new TryGetCallback((string s, out ScopeDefinition? def) =>
            {
                def = null;
                return false;
            }));

        var context = CreateContext(scopes: new[] { "openid", "unknown", "profile" });

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
    }

    /// <summary>
    /// Verifies offline_access check happens before scope manager validation.
    /// This ensures efficient rejection of unauthorized offline access requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OfflineAccessCheck_ShouldHappenFirst()
    {
        // Arrange - No scope manager setup, should fail on offline_access check first
        var context = CreateContext(
            scopes: new[] { "openid", "offline_access" },
            offlineAccessAllowed: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
        Assert.Contains("offline access", result.ErrorDescription);
        // Verify scope manager was never called
        _scopeManager.VerifyNoOtherCalls();
    }
}
