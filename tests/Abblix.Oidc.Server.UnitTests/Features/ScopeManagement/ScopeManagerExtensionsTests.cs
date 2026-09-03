// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ScopeManagement;

/// <summary>
/// Unit tests for <see cref="ScopeManagerExtensions"/> verifying scope validation logic
/// per OAuth 2.0 and OpenID Connect Core 1.0 specifications.
/// Tests cover scope validation against both ScopeManager and ResourceDefinitions.
/// </summary>
public class ScopeManagerExtensionsTests
{
    private readonly IScopeManager _scopeManager;

    public ScopeManagerExtensionsTests()
    {
        var customScopes = new[]
        {
            new ScopeDefinition("custom:read", "read_claim"),
            new ScopeDefinition("custom:write", "write_claim")
        };

        var options = Options.Create(new OidcOptions { Scopes = customScopes });
        _scopeManager = new ScopeManager(options);
    }

    /// <summary>
    /// Verifies validation succeeds with all valid standard scopes.
    /// Per OIDC Core, standard scopes (openid, profile, etc.) should be recognized.
    /// </summary>
    [Fact]
    public void Validate_WithStandardScopes_ShouldSucceed()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId, Scopes.Profile, Scopes.Email };

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Equal(3, definitions.Length);
        Assert.Contains(definitions, d => d.Scope == Scopes.OpenId);
        Assert.Contains(definitions, d => d.Scope == Scopes.Profile);
        Assert.Contains(definitions, d => d.Scope == Scopes.Email);
    }

    /// <summary>
    /// Verifies validation succeeds with custom scopes.
    /// Per OAuth 2.0, authorization servers may define custom scopes.
    /// </summary>
    [Fact]
    public void Validate_WithCustomScopes_ShouldSucceed()
    {
        // Arrange
        var scopes = new[] { "custom:read", "custom:write" };

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Equal(2, definitions.Length);
        Assert.Contains(definitions, d => d.Scope == "custom:read");
        Assert.Contains(definitions, d => d.Scope == "custom:write");
    }

    /// <summary>
    /// Verifies validation fails with unregistered scope.
    /// Per OAuth 2.0, only registered scopes should be accepted.
    /// </summary>
    [Fact]
    public void Validate_WithUnregisteredScope_ShouldFail()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId, "unknown-scope" };

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out var error);

        // Assert
        Assert.False(result);
        Assert.Null(definitions);
        Assert.NotNull(error);
        Assert.Equal("The scope is not available", error);
    }

    /// <summary>
    /// Verifies validation succeeds with resource scopes.
    /// Per RFC 8707 (Resource Indicators), resource-specific scopes should be validated.
    /// </summary>
    [Fact]
    public void Validate_WithResourceScopes_ShouldSucceed()
    {
        // Arrange
        var scopes = new[] { "resource:read", "resource:write" };
        var resources = new[]
        {
            new ResourceDefinition(new Uri("https://api.example.com"),
                new ScopeDefinition("resource:read", "read_claim"),
                new ScopeDefinition("resource:write", "write_claim"))
        };

        // Act
        var result = _scopeManager.Validate(scopes, resources, null, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        // Resource scopes don't add to definitions, they're just validated
        Assert.Empty(definitions);
    }

    /// <summary>
    /// Verifies validation with mixed scope and resource scopes.
    /// Scopes can be from both ScopeManager and ResourceDefinitions.
    /// </summary>
    [Fact]
    public void Validate_WithMixedScopes_ShouldSucceed()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId, "custom:read", "resource:api" };
        var resources = new[]
        {
            new ResourceDefinition(new Uri("https://api.example.com"),
                new ScopeDefinition("resource:api", "api_claim"))
        };

        // Act
        var result = _scopeManager.Validate(scopes, resources, null, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Equal(2, definitions.Length); // openid + custom:read (not resource:api)
        Assert.Contains(definitions, d => d.Scope == Scopes.OpenId);
        Assert.Contains(definitions, d => d.Scope == "custom:read");
    }

    /// <summary>
    /// Verifies validation with empty scopes collection.
    /// Edge case: no scopes requested.
    /// </summary>
    [Fact]
    public void Validate_WithEmptyScopes_ShouldSucceed()
    {
        // Arrange
        var scopes = Enumerable.Empty<string>();

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Empty(definitions);
    }

    /// <summary>
    /// Verifies validation with null resources parameter.
    /// Per OAuth 2.0, resources are optional.
    /// </summary>
    [Fact]
    public void Validate_WithNullResources_ShouldValidateAgainstScopeManagerOnly()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId, "custom:read" };

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Equal(2, definitions.Length);
    }

    /// <summary>
    /// Verifies validation with empty resources array.
    /// Edge case: empty resource list.
    /// </summary>
    [Fact]
    public void Validate_WithEmptyResources_ShouldValidateAgainstScopeManagerOnly()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId };
        var resources = Array.Empty<ResourceDefinition>();

        // Act
        var result = _scopeManager.Validate(scopes, resources, null, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Single(definitions);
    }

    /// <summary>
    /// Verifies validation fails when scope not in ScopeManager or resources.
    /// Both sources must be checked before failing.
    /// </summary>
    [Fact]
    public void Validate_WithScopeNotInEitherSource_ShouldFail()
    {
        // Arrange
        var scopes = new[] { "completely-unknown" };
        var resources = new[]
        {
            new ResourceDefinition(new Uri("https://api.example.com"),
                new ScopeDefinition("resource:api", "api_claim"))
        };

        // Act
        var result = _scopeManager.Validate(scopes, resources, null, out var definitions, out var error);

        // Assert
        Assert.False(result);
        Assert.Null(definitions);
        Assert.NotNull(error);
        Assert.Equal("The scope is not available", error);
    }

    /// <summary>
    /// Verifies validation preserves scope definition properties.
    /// ScopeDefinitions should be returned with all their claim types.
    /// </summary>
    [Fact]
    public void Validate_ShouldPreserveScopeDefinitionProperties()
    {
        // Arrange
        var scopes = new[] { "custom:read" };

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out _);

        // Assert
        Assert.True(result);
        Assert.NotNull(definitions);
        var definition = Assert.Single(definitions);
        Assert.Equal("custom:read", definition.Scope);
        Assert.Single(definition.ClaimTypes);
        Assert.Equal("read_claim", definition.ClaimTypes[0]);
    }

    /// <summary>
    /// Verifies scope validation is case-sensitive.
    /// Per OAuth 2.0, scope identifiers are case-sensitive.
    /// </summary>
    [Fact]
    public void Validate_IsCaseSensitive()
    {
        // Arrange
        var scopes = new[] { "OPENID" }; // Wrong case

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out var error);

        // Assert
        Assert.False(result);
        Assert.Null(definitions);
        Assert.NotNull(error);
    }

    /// <summary>
    /// Verifies duplicate scopes are included in results.
    /// Duplicate scopes should be allowed (may represent repeated consent).
    /// </summary>
    [Fact]
    public void Validate_WithDuplicateScopes_ShouldIncludeBoth()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId, Scopes.OpenId }; // Duplicate

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out _);

        // Assert
        Assert.True(result);
        Assert.NotNull(definitions);
        Assert.Equal(2, definitions.Length);
        Assert.All(definitions, d => Assert.Equal(Scopes.OpenId, d.Scope));
    }

    /// <summary>
    /// Verifies validation with multiple resources.
    /// Resource scopes from multiple resources should be validated.
    /// </summary>
    [Fact]
    public void Validate_WithMultipleResources_ShouldValidateAgainstAll()
    {
        // Arrange
        var scopes = new[] { "api1:read", "api2:write" };
        var resources = new[]
        {
            new ResourceDefinition(new Uri("https://api1.example.com"),
                new ScopeDefinition("api1:read", "read_claim")),
            new ResourceDefinition(new Uri("https://api2.example.com"),
                new ScopeDefinition("api2:write", "write_claim"))
        };

        // Act
        var result = _scopeManager.Validate(scopes, resources, null, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Empty(definitions); // Resource scopes don't add to definitions
    }

    /// <summary>
    /// Verifies resource with multiple scopes.
    /// A single resource may define multiple scopes.
    /// </summary>
    [Fact]
    public void Validate_WithResourceHavingMultipleScopes_ShouldValidate()
    {
        // Arrange
        var scopes = new[] { "api:read", "api:write", "api:delete" };
        var resources = new[]
        {
            new ResourceDefinition(new Uri("https://api.example.com"),
                new ScopeDefinition("api:read", "read_claim"),
                new ScopeDefinition("api:write", "write_claim"),
                new ScopeDefinition("api:delete", "delete_claim"))
        };

        // Act
        var result = _scopeManager.Validate(scopes, resources, null, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Empty(definitions);
    }

    /// <summary>
    /// Verifies first invalid scope stops validation.
    /// Validation fails fast on first error.
    /// </summary>
    [Fact]
    public void Validate_WithFirstScopeInvalid_ShouldFailImmediately()
    {
        // Arrange
        var scopes = new[] { "invalid", Scopes.OpenId };

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out var error);

        // Assert
        Assert.False(result);
        Assert.Null(definitions);
        Assert.NotNull(error);
        Assert.Equal("The scope is not available", error);
    }

    /// <summary>
    /// Verifies validation with offline_access scope.
    /// Per OIDC Core, offline_access is a standard scope for refresh tokens.
    /// </summary>
    [Fact]
    public void Validate_WithOfflineAccessScope_ShouldSucceed()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId, Scopes.OfflineAccess };

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Equal(2, definitions.Length);
        Assert.Contains(definitions, d => d.Scope == Scopes.OfflineAccess);
    }

    /// <summary>
    /// Verifies validation with all standard OIDC scopes.
    /// All 6 standard scopes should be recognized.
    /// </summary>
    [Fact]
    public void Validate_WithAllStandardScopes_ShouldSucceed()
    {
        // Arrange
        var scopes = new[]
        {
            Scopes.OpenId, Scopes.Profile, Scopes.Email,
            Scopes.Address, Scopes.Phone, Scopes.OfflineAccess
        };

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Equal(6, definitions.Length);
    }

    /// <summary>
    /// Verifies order of scopes is preserved.
    /// Scope order may be significant for some clients.
    /// </summary>
    [Fact]
    public void Validate_ShouldPreserveOrderOfScopes()
    {
        // Arrange
        var scopes = new[] { Scopes.Email, Scopes.Profile, Scopes.OpenId };

        // Act
        var result = _scopeManager.Validate(scopes, null, null, out var definitions, out _);

        // Assert
        Assert.True(result);
        Assert.NotNull(definitions);
        Assert.Equal(3, definitions.Length);
        Assert.Equal(Scopes.Email, definitions[0].Scope);
        Assert.Equal(Scopes.Profile, definitions[1].Scope);
        Assert.Equal(Scopes.OpenId, definitions[2].Scope);
    }

    /// <summary>
    /// Verifies a requested scope outside the client's allowed (registered) scope set is rejected.
    /// RFC 6749 section 3.3: the authorization server restricts scope by policy - a client must not obtain
    /// a scope it was never registered for, even if that scope is registered server-wide.
    /// </summary>
    [Fact]
    public void Validate_RequestedScopeNotInClientAllowedScopes_ShouldReject()
    {
        // Arrange - the scope is registered globally, but not in the client's allowed set.
        var scopes = new[] { Scopes.OpenId, Scopes.Profile };
        var allowedClientScopes = new[] { Scopes.OpenId };

        // Act
        var result = _scopeManager.Validate(scopes, null, allowedClientScopes, out var definitions, out _);

        // Assert
        Assert.False(result);
        Assert.Null(definitions);
    }

    /// <summary>
    /// Verifies a request confined to the client's allowed scope set succeeds.
    /// </summary>
    [Fact]
    public void Validate_RequestedScopesWithinClientAllowedScopes_ShouldSucceed()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId };
        var allowedClientScopes = new[] { Scopes.OpenId, Scopes.Profile };

        // Act
        var result = _scopeManager.Validate(scopes, null, allowedClientScopes, out var definitions, out _);

        // Assert
        Assert.True(result);
        Assert.NotNull(definitions);
    }

    /// <summary>
    /// Verifies an empty client allow-list imposes no per-client restriction (backward compatible),
    /// mirroring the per-issuer allow-list semantics of the JWT bearer grant.
    /// </summary>
    [Fact]
    public void Validate_EmptyClientAllowedScopes_ShouldNotRestrict()
    {
        // Arrange
        var scopes = new[] { Scopes.OpenId, Scopes.Profile };

        // Act
        var result = _scopeManager.Validate(scopes, null, [], out var definitions, out _);

        // Assert
        Assert.True(result);
        Assert.NotNull(definitions);
    }
}
