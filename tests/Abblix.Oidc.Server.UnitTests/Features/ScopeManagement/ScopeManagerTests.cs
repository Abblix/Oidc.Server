// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ScopeManagement;

/// <summary>
/// Unit tests for <see cref="ScopeManager"/> verifying scope registration and retrieval
/// per OpenID Connect Core 1.0 and OAuth 2.0 specifications.
/// Tests cover standard scope initialization, custom scopes, and scope lookup.
/// </summary>
public class ScopeManagerTests
{
    /// <summary>
    /// Verifies standard OIDC scopes are registered by default.
    /// Per OIDC Core, standard scopes (openid, profile, email, address, phone, offline_access) must be available.
    /// </summary>
    [Fact]
    public void Constructor_WithNoCustomScopes_ShouldRegisterStandardScopes()
    {
        // Arrange
        var options = Options.Create(new OidcOptions());

        // Act
        var manager = new ScopeManager(options);

        // Assert - Standard OIDC scopes
        Assert.True(manager.TryGet(Scopes.OpenId, out var openId));
        Assert.Equal(Scopes.OpenId, openId.Scope);

        Assert.True(manager.TryGet(Scopes.Profile, out var profile));
        Assert.Equal(Scopes.Profile, profile.Scope);

        Assert.True(manager.TryGet(Scopes.Email, out var email));
        Assert.Equal(Scopes.Email, email.Scope);

        Assert.True(manager.TryGet(Scopes.Address, out var address));
        Assert.Equal(Scopes.Address, address.Scope);

        Assert.True(manager.TryGet(Scopes.Phone, out var phone));
        Assert.Equal(Scopes.Phone, phone.Scope);

        Assert.True(manager.TryGet(Scopes.OfflineAccess, out var offlineAccess));
        Assert.Equal(Scopes.OfflineAccess, offlineAccess.Scope);
    }

    /// <summary>
    /// Verifies custom scopes can be added via configuration.
    /// Per OAuth 2.0, authorization servers may define custom scopes.
    /// </summary>
    [Fact]
    public void Constructor_WithCustomScopes_ShouldRegisterCustomScopes()
    {
        // Arrange
        var customScope = new ScopeDefinition("custom:read", "claim1", "claim2");

        var options = Options.Create(new OidcOptions
        {
            Scopes = [customScope]
        });

        // Act
        var manager = new ScopeManager(options);

        // Assert
        Assert.True(manager.TryGet("custom:read", out var retrieved));
        Assert.Equal("custom:read", retrieved.Scope);
        Assert.Equal(2, retrieved.ClaimTypes.Length);
        Assert.Contains("claim1", retrieved.ClaimTypes);
        Assert.Contains("claim2", retrieved.ClaimTypes);
    }

    /// <summary>
    /// Verifies multiple custom scopes can be registered.
    /// Authorization servers typically define multiple custom scopes.
    /// </summary>
    [Fact]
    public void Constructor_WithMultipleCustomScopes_ShouldRegisterAll()
    {
        // Arrange
        var scopes = new[]
        {
            new ScopeDefinition("api:read"),
            new ScopeDefinition("api:write"),
            new ScopeDefinition("admin")
        };

        var options = Options.Create(new OidcOptions { Scopes = scopes });

        // Act
        var manager = new ScopeManager(options);

        // Assert
        Assert.True(manager.TryGet("api:read", out _));
        Assert.True(manager.TryGet("api:write", out _));
        Assert.True(manager.TryGet("admin", out _));
    }

    /// <summary>
    /// Verifies TryGet returns false for unregistered scope.
    /// Per OAuth 2.0, only registered scopes should be recognized.
    /// </summary>
    [Fact]
    public void TryGet_WithUnregisteredScope_ShouldReturnFalse()
    {
        // Arrange
        var options = Options.Create(new OidcOptions());
        var manager = new ScopeManager(options);

        // Act
        var result = manager.TryGet("unknown-scope", out var definition);

        // Assert
        Assert.False(result);
        Assert.Null(definition);
    }

    /// <summary>
    /// Verifies scope lookup is case-sensitive.
    /// Per OAuth 2.0, scope identifiers are case-sensitive.
    /// </summary>
    [Fact]
    public void TryGet_IsCaseSensitive()
    {
        // Arrange
        var options = Options.Create(new OidcOptions());
        var manager = new ScopeManager(options);

        // Act & Assert
        Assert.True(manager.TryGet(Scopes.OpenId, out _)); // "openid" - correct case
        Assert.False(manager.TryGet("OpenId", out _)); // Wrong case
        Assert.False(manager.TryGet("OPENID", out _)); // Wrong case
    }

    /// <summary>
    /// Verifies a host definition under a standard scope name extends that scope: the standard
    /// claims survive and the host's additions join them. Redefinition can therefore neither
    /// narrow what OIDC Core assigns to the scope nor be silently discarded.
    /// </summary>
    [Fact]
    public void Constructor_CustomScopeSameAsStandard_ShouldExtendStandardClaims()
    {
        // Arrange
        var customProfile = new ScopeDefinition(Scopes.Profile, "custom_claim");

        var options = Options.Create(new OidcOptions
        {
            Scopes = [customProfile]
        });

        // Act
        var manager = new ScopeManager(options);

        // Assert
        Assert.True(manager.TryGet(Scopes.Profile, out var retrieved));
        foreach (var standardClaim in StandardScopes.Profile.ClaimTypes)
            Assert.Contains(standardClaim, retrieved.ClaimTypes);
        Assert.Contains("custom_claim", retrieved.ClaimTypes);
    }

    /// <summary>
    /// Verifies extension never duplicates a claim the standard scope already carries: the merge
    /// is a set union, so a host restating a standard claim adds nothing.
    /// </summary>
    [Fact]
    public void Constructor_CustomScopeRestatingStandardClaim_ShouldNotDuplicateIt()
    {
        // Arrange
        var restated = StandardScopes.Email.ClaimTypes[0];
        var options = Options.Create(new OidcOptions
        {
            Scopes = [new ScopeDefinition(Scopes.Email, restated)]
        });

        // Act
        var manager = new ScopeManager(options);

        // Assert
        Assert.True(manager.TryGet(Scopes.Email, out var retrieved));
        Assert.Single(retrieved.ClaimTypes, claim => claim == restated);
    }

    /// <summary>
    /// Verifies ScopeManager is enumerable.
    /// IScopeManager extends IEnumerable{ScopeDefinition}.
    /// </summary>
    [Fact]
    public void GetEnumerator_ShouldEnumerateAllScopes()
    {
        // Arrange
        var customScope = new ScopeDefinition("custom");
        var options = Options.Create(new OidcOptions { Scopes = [customScope] });
        var manager = new ScopeManager(options);

        // Act
        var scopes = manager.ToArray();

        // Assert
        // 6 standard scopes + 1 custom
        Assert.Equal(7, scopes.Length);
        Assert.Contains(scopes, s => s.Scope == Scopes.OpenId);
        Assert.Contains(scopes, s => s.Scope == Scopes.Profile);
        Assert.Contains(scopes, s => s.Scope == Scopes.Email);
        Assert.Contains(scopes, s => s.Scope == Scopes.Address);
        Assert.Contains(scopes, s => s.Scope == Scopes.Phone);
        Assert.Contains(scopes, s => s.Scope == Scopes.OfflineAccess);
        Assert.Contains(scopes, s => s.Scope == "custom");
    }

    /// <summary>
    /// Verifies empty custom scopes array doesn't cause issues.
    /// Edge case: empty configuration.
    /// </summary>
    [Fact]
    public void Constructor_WithEmptyCustomScopesArray_ShouldRegisterStandardScopesOnly()
    {
        // Arrange
        var options = Options.Create(new OidcOptions { Scopes = [] });

        // Act
        var manager = new ScopeManager(options);
        var scopes = manager.ToArray();

        // Assert
        Assert.Equal(6, scopes.Length); // Only standard scopes
        Assert.All(scopes, s => Assert.Contains(s.Scope, new[]
        {
            Scopes.OpenId, Scopes.Profile, Scopes.Email,
            Scopes.Address, Scopes.Phone, Scopes.OfflineAccess
        }));
    }

    /// <summary>
    /// Verifies null custom scopes in options is handled.
    /// Edge case: null configuration.
    /// </summary>
    [Fact]
    public void Constructor_WithNullCustomScopes_ShouldRegisterStandardScopesOnly()
    {
        // Arrange
        var options = Options.Create(new OidcOptions { Scopes = null });

        // Act
        var manager = new ScopeManager(options);
        var scopes = manager.ToArray();

        // Assert
        Assert.Equal(6, scopes.Length); // Only standard scopes
    }

    /// <summary>
    /// Verifies scope definitions preserve all properties.
    /// ScopeDefinition contains Scope, Description, and Resources.
    /// </summary>
    [Fact]
    public void TryGet_ShouldPreserveScopeDefinitionProperties()
    {
        // Arrange
        var customScope = new ScopeDefinition("api:full", "claim1", "claim2", "claim3");

        var options = Options.Create(new OidcOptions { Scopes = [customScope] });
        var manager = new ScopeManager(options);

        // Act
        var result = manager.TryGet("api:full", out var definition);

        // Assert
        Assert.True(result);
        Assert.Equal("api:full", definition!.Scope);
        Assert.Equal(3, definition.ClaimTypes.Length);
        Assert.Contains("claim1", definition.ClaimTypes);
        Assert.Contains("claim2", definition.ClaimTypes);
        Assert.Contains("claim3", definition.ClaimTypes);
    }

    /// <summary>
    /// Verifies standard scope definitions have expected claim types.
    /// Standard scopes should map to specific OIDC claims.
    /// </summary>
    [Fact]
    public void TryGet_StandardScopes_ShouldHaveClaimTypes()
    {
        // Arrange
        var options = Options.Create(new OidcOptions());
        var manager = new ScopeManager(options);

        // Act & Assert - openid scope
        Assert.True(manager.TryGet(Scopes.OpenId, out var openId));
        Assert.NotNull(openId.ClaimTypes);
        Assert.NotEmpty(openId.ClaimTypes);
        Assert.Contains("sub", openId.ClaimTypes);

        // Act & Assert - profile scope
        Assert.True(manager.TryGet(Scopes.Profile, out var profile));
        Assert.NotNull(profile.ClaimTypes);
        Assert.NotEmpty(profile.ClaimTypes);
        Assert.Contains("name", profile.ClaimTypes);
    }

    /// <summary>
    /// Verifies duplicate custom scopes are handled (first wins).
    /// Duplicate definitions merge into one scope carrying the union of their claims, matching
    /// how a redefined standard scope is treated.
    /// </summary>
    [Fact]
    public void Constructor_WithDuplicateCustomScopes_ShouldMergeClaims()
    {
        // Arrange
        var scopes = new[]
        {
            new ScopeDefinition("duplicate", "claim1"),
            new ScopeDefinition("duplicate", "claim2")
        };

        var options = Options.Create(new OidcOptions { Scopes = scopes });

        // Act
        var manager = new ScopeManager(options);

        // Assert
        Assert.True(manager.TryGet("duplicate", out var definition));
        Assert.Equal(["claim1", "claim2"], definition.ClaimTypes);
    }

    /// <summary>
    /// Verifies enumeration doesn't return duplicates.
    /// Dictionary-based storage ensures unique scopes.
    /// </summary>
    [Fact]
    public void GetEnumerator_WithDuplicates_ShouldNotReturnDuplicates()
    {
        // Arrange
        var scopes = new[]
        {
            new ScopeDefinition("api"),
            new ScopeDefinition("api") // Duplicate
        };

        var options = Options.Create(new OidcOptions { Scopes = scopes });
        var manager = new ScopeManager(options);

        // Act
        var allScopes = manager.ToArray();
        var apiScopes = allScopes.Where(s => s.Scope == "api").ToArray();

        // Assert
        Assert.Single(apiScopes); // Only one "api" scope
    }
}
