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
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="ScopeValidator"/> verifying scope validation per OAuth 2.0 RFC 6749
/// and OIDC Core 1.0. Tests cover offline_access handling, scope availability validation,
/// client authorization checks, and flow-specific restrictions.
/// </summary>
public class ScopeValidatorTests
{
    private const string ClientId = "client_123";

    private readonly Mock<IScopeManager> _scopeManager;
    private readonly ScopeValidator _validator;

    private readonly ScopeDefinition _openIdScope;
    private readonly ScopeDefinition _profileScope;
    private readonly ScopeDefinition _emailScope;
    private readonly ScopeDefinition _offlineAccessScope;

    public ScopeValidatorTests()
    {
        _scopeManager = new Mock<IScopeManager>();
        _validator = new ScopeValidator(_scopeManager.Object);

        // Setup standard scope definitions
        _openIdScope = new ScopeDefinition(Scopes.OpenId);
        _profileScope = new ScopeDefinition(Scopes.Profile, "name", "given_name", "family_name");
        _emailScope = new ScopeDefinition(Scopes.Email, "email", "email_verified");
        _offlineAccessScope = new ScopeDefinition(Scopes.OfflineAccess);

        // Setup default scope manager behavior
        SetupScopeManager();
    }

    /// <summary>
    /// Configures the mock scope manager with standard scopes.
    /// </summary>
    private void SetupScopeManager()
    {
        _scopeManager.Setup(m => m.TryGet(Scopes.OpenId, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((string scope, out ScopeDefinition? definition) =>
            {
                definition = _openIdScope;
                return true;
            }));

        _scopeManager.Setup(m => m.TryGet(Scopes.Profile, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((string scope, out ScopeDefinition? definition) =>
            {
                definition = _profileScope;
                return true;
            }));

        _scopeManager.Setup(m => m.TryGet(Scopes.Email, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((string scope, out ScopeDefinition? definition) =>
            {
                definition = _emailScope;
                return true;
            }));

        _scopeManager.Setup(m => m.TryGet(Scopes.OfflineAccess, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((string scope, out ScopeDefinition? definition) =>
            {
                definition = _offlineAccessScope;
                return true;
            }));
    }

    // Delegate for Moq out parameter support
    private delegate bool ScopeManagerTryGetCallback(string scope, out ScopeDefinition? definition);

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(
        string[] scopes,
        FlowTypes flowType = FlowTypes.AuthorizationCode,
        bool? offlineAccessAllowed = null,
        ResourceDefinition[]? resources = null)
    {
        var request = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = scopes,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            OfflineAccessAllowed = offlineAccessAllowed,
        };

        return new AuthorizationValidationContext(request)
        {
            ClientInfo = clientInfo,
            FlowType = flowType,
            ResponseMode = ResponseModes.Query,
            Resources = resources ?? [],
        };
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts standard scopes.
    /// Per OIDC Core 1.0, openid, profile, email are standard scopes.
    /// Tests basic scope validation success path.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithStandardScopes_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([Scopes.OpenId, Scopes.Profile, Scopes.Email]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.Scope);
        Assert.Equal(3, context.Scope.Length);
        Assert.Contains(context.Scope, s => s.Scope == Scopes.OpenId);
        Assert.Contains(context.Scope, s => s.Scope == Scopes.Profile);
        Assert.Contains(context.Scope, s => s.Scope == Scopes.Email);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts offline_access for authorization code flow.
    /// Per OIDC Core 1.0 Section 11, offline_access is allowed for code flow.
    /// Critical for refresh token issuance.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OfflineAccessInAuthorizationCodeFlow_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            FlowTypes.AuthorizationCode,
            offlineAccessAllowed: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects offline_access for implicit flow.
    /// Per OIDC Core 1.0, offline_access MUST NOT be used with implicit flow.
    /// Critical security requirement (implicit can't securely store refresh tokens).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OfflineAccessInImplicitFlow_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            FlowTypes.Implicit,
            offlineAccessAllowed: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
        Assert.Contains("implicit", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("offline", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts offline_access for hybrid flow.
    /// Per OIDC Core 1.0, offline_access is allowed for hybrid flow.
    /// Tests hybrid flow refresh token capability.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OfflineAccessInHybridFlow_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            FlowTypes.Hybrid,
            offlineAccessAllowed: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects offline_access when client not authorized.
    /// Per client configuration, offline_access must be explicitly allowed.
    /// Critical security check preventing unauthorized refresh token issuance.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OfflineAccessWhenClientNotAuthorized_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            FlowTypes.AuthorizationCode,
            offlineAccessAllowed: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
        Assert.Contains("not allowed", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("offline", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects offline_access when OfflineAccessAllowed is null.
    /// Per validation logic, OfflineAccessAllowed must be explicitly true (not null or false).
    /// Tests strict authorization requirement.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OfflineAccessWhenNotExplicitlyAllowed_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            FlowTypes.AuthorizationCode,
            offlineAccessAllowed: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects unknown/unregistered scopes.
    /// Per OAuth 2.0, only registered scopes are valid.
    /// Critical for preventing scope injection attacks.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnknownScope_ShouldReturnError()
    {
        // Arrange
        _scopeManager.Setup(m => m.TryGet("unknown_scope", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((string scope, out ScopeDefinition? definition) =>
            {
                definition = null!;
                return false;
            }));

        var context = CreateContext([Scopes.OpenId, "unknown_scope"]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
        Assert.Contains("not available", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts resource-specific scopes.
    /// Per RFC 8707 Resource Indicators, scopes can be resource-specific.
    /// Tests scope validation against resource definitions.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithResourceScope_ShouldSucceed()
    {
        // Arrange
        var resourceScopes = new[]
        {
            new ScopeDefinition("resource:read"),
            new ScopeDefinition("resource:write"),
        };

        var resources = new[]
        {
            new ResourceDefinition(new Uri("https://api.example.com"), resourceScopes),
        };

        var context = CreateContext([Scopes.OpenId, "resource:read"], resources: resources);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Single(context.Scope); // Only openid is in scope manager, resource:read is in resource
        Assert.Contains(context.Scope, s => s.Scope == Scopes.OpenId);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts only openid scope.
    /// Per OIDC Core 1.0, minimal valid request needs only openid scope.
    /// Tests minimal scope requirement.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithOnlyOpenIdScope_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([Scopes.OpenId]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Single(context.Scope);
        Assert.Equal(Scopes.OpenId, context.Scope[0].Scope);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles empty scope array.
    /// Per OAuth 2.0, scope is required but validator handles edge case.
    /// Tests defensive programming for malformed requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyScopes_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Empty(context.Scope);
    }

    /// <summary>
    /// Verifies that ValidateAsync sets context.Scope on successful validation.
    /// Per validator contract, context must be populated with validated scopes.
    /// Critical for downstream authorization flow processing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldPopulateContextScope()
    {
        // Arrange
        var context = CreateContext([Scopes.OpenId, Scopes.Profile]);
        Assert.Empty(context.Scope);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotEmpty(context.Scope);
        Assert.Equal(2, context.Scope.Length);
    }

    /// <summary>
    /// Verifies that ValidateAsync does not set context.Scope on failure.
    /// Failed validation should not modify context.Scope.
    /// Ensures error state consistency.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnFailure_ShouldNotPopulateContextScope()
    {
        // Arrange
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            FlowTypes.Implicit,
            offlineAccessAllowed: true);
        var originalScope = context.Scope;

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Same(originalScope, context.Scope);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes redirect URI in error response.
    /// Per OAuth 2.0, error responses should include redirect_uri when available.
    /// Critical for proper error flow completion.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeRedirectUri()
    {
        // Arrange
        var redirectUri = new Uri("https://client.example.com/callback");
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            FlowTypes.Implicit,
            offlineAccessAllowed: true);
        context.ValidRedirectUri = redirectUri;

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(redirectUri, result.RedirectUri);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes response mode in error response.
    /// Per OAuth 2.0, error delivery must match requested response mode.
    /// Critical for proper error communication channel.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeResponseMode()
    {
        // Arrange
        const string responseMode = ResponseModes.Fragment;
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            FlowTypes.Implicit,
            offlineAccessAllowed: true);
        context.ResponseMode = responseMode;

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(responseMode, result.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts multiple standard scopes.
    /// Tests validator handles typical multi-scope request.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleStandardScopes_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext([Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Address, Scopes.Phone]);

        // Setup additional scopes
        _scopeManager.Setup(m => m.TryGet(Scopes.Address, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((string scope, out ScopeDefinition? definition) =>
            {
                definition = new ScopeDefinition(Scopes.Address);
                return true;
            }));

        _scopeManager.Setup(m => m.TryGet(Scopes.Phone, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((string scope, out ScopeDefinition? definition) =>
            {
                definition = new ScopeDefinition(Scopes.Phone);
                return true;
            }));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(5, context.Scope.Length);
    }

    /// <summary>
    /// Verifies that ValidateAsync preserves scope order.
    /// Tests that validated scopes maintain request order.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPreserveScopeOrder()
    {
        // Arrange
        var context = CreateContext([Scopes.Email, Scopes.Profile, Scopes.OpenId]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(3, context.Scope.Length);
        Assert.Equal(Scopes.Email, context.Scope[0].Scope);
        Assert.Equal(Scopes.Profile, context.Scope[1].Scope);
        Assert.Equal(Scopes.OpenId, context.Scope[2].Scope);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles duplicate scopes.
    /// Per OAuth 2.0, duplicate scopes should be processed (not filtered).
    /// Tests validator doesn't deduplicate scopes.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDuplicateScopes_ShouldProcessAll()
    {
        // Arrange
        var context = CreateContext([Scopes.OpenId, Scopes.Profile, Scopes.OpenId]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(3, context.Scope.Length); // All three processed including duplicate
    }

    /// <summary>
    /// Verifies that ValidateAsync checks offline_access before other validation.
    /// Tests validation order (offline_access checked first).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithOfflineAccessAndUnknownScope_ShouldFailOnOfflineAccess()
    {
        // Arrange
        _scopeManager.Setup(m => m.TryGet("unknown", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((string scope, out ScopeDefinition? definition) =>
            {
                definition = null!;
                return false;
            }));

        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess, "unknown"],
            FlowTypes.Implicit,
            offlineAccessAllowed: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
        Assert.Contains("implicit", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes ScopeDefinition with claim types.
    /// Per OIDC Core 1.0, scopes map to specific claim types.
    /// Tests that scope definitions include associated claims.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldIncludeScopeClaimTypes()
    {
        // Arrange
        var context = CreateContext([Scopes.Profile]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Single(context.Scope);
        var profileScope = context.Scope[0];
        Assert.Equal(Scopes.Profile, profileScope.Scope);
        Assert.Contains("name", profileScope.ClaimTypes);
        Assert.Contains("given_name", profileScope.ClaimTypes);
        Assert.Contains("family_name", profileScope.ClaimTypes);
    }

    /// <summary>
    /// Verifies that ValidateAsync combines manager scopes and resource scopes.
    /// Tests validator correctly merges scope sources.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMixedManagerAndResourceScopes_ShouldSucceed()
    {
        // Arrange
        var resources = new[]
        {
            new ResourceDefinition(
                new Uri("https://api.example.com"),
                new ScopeDefinition("api:read"),
                new ScopeDefinition("api:write")),
        };

        var context = CreateContext([Scopes.OpenId, "api:read", Scopes.Profile], resources: resources);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(2, context.Scope.Length); // openid and profile from manager, api:read from resource
        Assert.Contains(context.Scope, s => s.Scope == Scopes.OpenId);
        Assert.Contains(context.Scope, s => s.Scope == Scopes.Profile);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects scope not in manager or resources.
    /// Tests comprehensive scope validation across both sources.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithScopeInNeitherManagerNorResources_ShouldReturnError()
    {
        // Arrange
        _scopeManager.Setup(m => m.TryGet("custom_scope", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((string scope, out ScopeDefinition? definition) =>
            {
                definition = null!;
                return false;
            }));

        var resources = new[]
        {
            new ResourceDefinition(
                new Uri("https://api.example.com"),
                new ScopeDefinition("api:read")),
        };

        var context = CreateContext([Scopes.OpenId, "custom_scope"], resources: resources);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
    }
}
