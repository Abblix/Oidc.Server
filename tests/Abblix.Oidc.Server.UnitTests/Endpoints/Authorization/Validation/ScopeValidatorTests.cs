// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="ScopeValidator"/> verifying scope validation per OAuth 2.0 RFC 6749
/// and OIDC Core 1.0. Tests cover offline_access handling, scope availability validation,
/// client authorization checks, and flow-specific restrictions.
/// </summary>
public class ScopeValidatorTests
{
    private const string ClientId = TestConstants.DefaultClientId;

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
        _scopeManager.Setup(m => m.TryGet(TestTenant.Matched, Scopes.OpenId, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
            {
                definition = _openIdScope;
                return true;
            }));

        _scopeManager.Setup(m => m.TryGet(TestTenant.Matched, Scopes.Profile, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
            {
                definition = _profileScope;
                return true;
            }));

        _scopeManager.Setup(m => m.TryGet(TestTenant.Matched, Scopes.Email, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
            {
                definition = _emailScope;
                return true;
            }));

        _scopeManager.Setup(m => m.TryGet(TestTenant.Matched, Scopes.OfflineAccess, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
            {
                definition = _offlineAccessScope;
                return true;
            }));
    }

    // Delegate for Moq out parameter support
    private delegate bool ScopeManagerTryGetCallback(TenantDefinition tenant, string scope, out ScopeDefinition? definition);

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(
        string[] scopes,
        FlowTypes flowType = FlowTypes.AuthorizationCode,
        OfflineAccess offlineAccess = OfflineAccess.Disabled,
        ResourceDefinition[]? resources = null,
        string[]? prompt = null,
        string[]? responseType = null)
    {
        var request = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = responseType ?? [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = scopes,
            Prompt = prompt,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            OfflineAccess = offlineAccess,
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.Scope);
        Assert.Equal(3, context.Scope.Length);
        Assert.Contains(context.Scope, s => s.Scope == Scopes.OpenId);
        Assert.Contains(context.Scope, s => s.Scope == Scopes.Profile);
        Assert.Contains(context.Scope, s => s.Scope == Scopes.Email);
    }

    /// <summary>
    /// OpenID Connect Core 1.0, sections 11 and 17.4: a request returning an authorization code and no access token
    /// through the user agent receives offline_access when it asks for consent with prompt=consent, or when the
    /// client is configured to receive it without, and has it ignored otherwise, the rest of the request going on.
    /// Ignored, it leaves the request itself too, which the host's consent provider reads.
    /// </summary>
    [Theory]
    [InlineData(FlowTypes.AuthorizationCode, "code", true, OfflineAccess.ConsentRequired, true)]
    [InlineData(FlowTypes.AuthorizationCode, "code", false, OfflineAccess.Allowed, true)]
    [InlineData(FlowTypes.AuthorizationCode, "code", false, OfflineAccess.ConsentRequired, false)]
    [InlineData(FlowTypes.Hybrid, "code id_token", true, OfflineAccess.ConsentRequired, true)]
    [InlineData(FlowTypes.Hybrid, "code id_token", false, OfflineAccess.ConsentRequired, false)]
    [InlineData(FlowTypes.Hybrid, "code token", true, OfflineAccess.Allowed, false)]
    [InlineData(FlowTypes.Hybrid, "code id_token token", true, OfflineAccess.Allowed, false)]
    [InlineData(FlowTypes.None, "none", true, OfflineAccess.Allowed, false)]
    public async Task ValidateAsync_OfflineAccess_IsReceivedOnlyWithConsentPromptOrClientConditions(
        FlowTypes flowType, string responseType, bool promptConsent, OfflineAccess offlineAccess, bool received)
    {
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            flowType,
            offlineAccess: offlineAccess,
            prompt: promptConsent ? [Prompts.Consent] : null,
            responseType: responseType.Split(' '));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Null(result);
        Assert.Equal(received, Array.Exists(context.Scope, scope => scope.Scope == Scopes.OfflineAccess));
        Assert.Equal(received, Array.IndexOf(context.Request.Scope, Scopes.OfflineAccess) >= 0);
        Assert.Contains(context.Scope, scope => scope.Scope == Scopes.OpenId);
    }

    /// <summary>
    /// OpenID Connect Core 1.0, section 11: a response returning no authorization code has offline_access ignored,
    /// however the request asks, rather than refused.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OfflineAccessInImplicitFlow_IsIgnored()
    {
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            FlowTypes.Implicit,
            offlineAccess: OfflineAccess.Allowed,
            prompt: [Prompts.Consent],
            responseType: [ResponseTypes.IdToken, ResponseTypes.Token]);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Null(result);
        Assert.DoesNotContain(context.Scope, scope => scope.Scope == Scopes.OfflineAccess);
        Assert.DoesNotContain(Scopes.OfflineAccess, context.Request.Scope);
        Assert.Contains(context.Scope, scope => scope.Scope == Scopes.OpenId);
    }

    /// <summary>
    /// A client not allowed offline access is refused only for a request that would otherwise receive it: where
    /// OpenID Connect Core 1.0 has the server ignore offline_access, it is ignored for this client too.
    /// </summary>
    [Theory]
    [InlineData(FlowTypes.AuthorizationCode, "code", true, true)]
    [InlineData(FlowTypes.AuthorizationCode, "code", false, false)]
    [InlineData(FlowTypes.Implicit, "id_token token", true, false)]
    [InlineData(FlowTypes.Hybrid, "code token", true, false)]
    public async Task ValidateAsync_OfflineAccessWhenClientNotAuthorized_IsRefusedOnlyWhereReceived(
        FlowTypes flowType, string responseType, bool promptConsent, bool refused)
    {
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            flowType,
            offlineAccess: OfflineAccess.Disabled,
            prompt: promptConsent ? [Prompts.Consent] : null,
            responseType: responseType.Split(' '));

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(refused ? ErrorCodes.InvalidScope : null, result?.Error);
        Assert.Equal(refused, Array.IndexOf(context.Request.Scope, Scopes.OfflineAccess) >= 0);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects offline_access from a client left with the default offline access,
    /// Disabled: offline access is the host's explicit grant.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OfflineAccessWhenDisabledByDefault_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess],
            prompt: [Prompts.Consent]);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        _scopeManager.Setup(m => m.TryGet(TestTenant.Matched, "unknown_scope", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
            {
                definition = null!;
                return false;
            }));

        var context = CreateContext([Scopes.OpenId, "unknown_scope"]);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
            offlineAccess: OfflineAccess.Disabled,
            prompt: [Prompts.Consent]);
        var originalScope = context.Scope;

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
            offlineAccess: OfflineAccess.Disabled,
            prompt: [Prompts.Consent]);
        context.ValidRedirectUri = redirectUri;

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
            offlineAccess: OfflineAccess.Disabled,
            prompt: [Prompts.Consent]);
        context.ResponseMode = responseMode;

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        _scopeManager.Setup(m => m.TryGet(TestTenant.Matched, Scopes.Address, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
            {
                definition = new ScopeDefinition(Scopes.Address);
                return true;
            }));

        _scopeManager.Setup(m => m.TryGet(TestTenant.Matched, Scopes.Phone, out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
            {
                definition = new ScopeDefinition(Scopes.Phone);
                return true;
            }));

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        _scopeManager.Setup(m => m.TryGet(TestTenant.Matched, "unknown", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
            {
                definition = null!;
                return false;
            }));

        var context = CreateContext(
            [Scopes.OpenId, Scopes.OfflineAccess, "unknown"],
            offlineAccess: OfflineAccess.Disabled,
            prompt: [Prompts.Consent]);

        // Act
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
        _scopeManager.Verify(m => m.TryGet(It.IsAny<TenantDefinition>(), "unknown", out It.Ref<ScopeDefinition?>.IsAny), Times.Never);
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        _scopeManager.Setup(m => m.TryGet(TestTenant.Matched, "custom_scope", out It.Ref<ScopeDefinition?>.IsAny))
            .Returns(new ScopeManagerTryGetCallback((TenantDefinition _, string scope, out ScopeDefinition? definition) =>
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidScope, result.Error);
    }
}
