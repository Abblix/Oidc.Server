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
using System.Linq;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ResourceIndicators;

/// <summary>
/// Unit tests for <see cref="ResourceManagerExtensions"/> verifying OAuth 2.0 RFC 8707
/// (Resource Indicators for OAuth 2.0) validation logic.
/// Tests cover absolute URI requirements, fragment prohibition, unknown resource handling,
/// and scope filtering.
/// </summary>
public class ResourceManagerExtensionsTests
{
    private readonly IResourceManager _resourceManager;

    public ResourceManagerExtensionsTests()
    {
        var resource1 = new ResourceDefinition(
            new Uri("https://api1.example.com"),
            new ScopeDefinition("api1:read", "read_claim"),
            new ScopeDefinition("api1:write", "write_claim"));

        var resource2 = new ResourceDefinition(
            new Uri("https://api2.example.com"),
            new ScopeDefinition("api2:admin", "admin_claim"));

        var options = Options.Create(new OidcOptions
        {
            Resources = [resource1, resource2]
        });

        _resourceManager = new ResourceManager(options);
    }

    /// <summary>
    /// Verifies validation succeeds with valid absolute URI.
    /// Per RFC 8707, resource URIs MUST be absolute URIs.
    /// </summary>
    [Fact]
    public void Validate_WithValidAbsoluteUri_ShouldSucceed()
    {
        // Arrange
        var resources = new[] { new Uri("https://api1.example.com") };
        var scopes = new[] { "api1:read" };

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Single(definitions);
        Assert.Equal(new Uri("https://api1.example.com"), definitions[0].Resource);
    }

    /// <summary>
    /// Verifies validation fails with relative URI.
    /// Per RFC 8707, resource parameter value MUST be an absolute URI.
    /// </summary>
    [Fact]
    public void Validate_WithRelativeUri_ShouldFail()
    {
        // Arrange
        var resources = new[] { new Uri("/api/resource", UriKind.Relative) };
        var scopes = new[] { "api:read" };

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.False(result);
        Assert.Null(definitions);
        Assert.NotNull(error);
        Assert.Equal("The resource must be absolute URI", error);
    }

    /// <summary>
    /// Verifies validation fails when URI contains fragment.
    /// Per RFC 8707, the requested resource URI MUST NOT include a fragment component.
    /// </summary>
    [Fact]
    public void Validate_WithFragment_ShouldFail()
    {
        // Arrange
        var resources = new[] { new Uri("https://api1.example.com#fragment") };
        var scopes = new[] { "api1:read" };

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.False(result);
        Assert.Null(definitions);
        Assert.NotNull(error);
        Assert.Equal("The requested resource must not contain fragment part", error);
    }

    /// <summary>
    /// Verifies validation fails with unknown resource.
    /// Per RFC 8707, authorization server should reject request if resource is unacceptable.
    /// </summary>
    [Fact]
    public void Validate_WithUnknownResource_ShouldFail()
    {
        // Arrange
        var resources = new[] { new Uri("https://unknown.example.com") };
        var scopes = new[] { "unknown:read" };

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.False(result);
        Assert.Null(definitions);
        Assert.NotNull(error);
        Assert.Equal("The requested resource is unknown", error);
    }

    /// <summary>
    /// Verifies scope filtering for single resource.
    /// Only requested scopes should be included in resource definition.
    /// </summary>
    [Fact]
    public void Validate_WithSingleScope_ShouldFilterScopes()
    {
        // Arrange
        var resources = new[] { new Uri("https://api1.example.com") };
        var scopes = new[] { "api1:read" }; // Only requesting read, not write

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        var definition = Assert.Single(definitions);
        Assert.Equal(new Uri("https://api1.example.com"), definition.Resource);
        Assert.Single(definition.Scopes);
        Assert.Equal("api1:read", definition.Scopes[0].Scope);
    }

    /// <summary>
    /// Verifies scope filtering with multiple scopes.
    /// All requested scopes for resource should be included.
    /// </summary>
    [Fact]
    public void Validate_WithMultipleScopes_ShouldFilterScopes()
    {
        // Arrange
        var resources = new[] { new Uri("https://api1.example.com") };
        var scopes = new[] { "api1:read", "api1:write" }; // Both scopes

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        var definition = Assert.Single(definitions);
        Assert.Equal(new Uri("https://api1.example.com"), definition.Resource);
        Assert.Equal(2, definition.Scopes.Length);
        Assert.Contains(definition.Scopes, s => s.Scope == "api1:read");
        Assert.Contains(definition.Scopes, s => s.Scope == "api1:write");
    }

    /// <summary>
    /// Verifies validation with multiple resources.
    /// Each resource should be validated and scopes filtered independently.
    /// </summary>
    [Fact]
    public void Validate_WithMultipleResources_ShouldValidateAll()
    {
        // Arrange
        var resources = new[]
        {
            new Uri("https://api1.example.com"),
            new Uri("https://api2.example.com")
        };
        var scopes = new[] { "api1:read", "api2:admin" };

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Equal(2, definitions.Length);

        var def1 = definitions.First(d => d.Resource.AbsoluteUri == "https://api1.example.com/");
        Assert.Single(def1.Scopes);
        Assert.Equal("api1:read", def1.Scopes[0].Scope);

        var def2 = definitions.First(d => d.Resource.AbsoluteUri == "https://api2.example.com/");
        Assert.Single(def2.Scopes);
        Assert.Equal("api2:admin", def2.Scopes[0].Scope);
    }

    /// <summary>
    /// Verifies validation with empty resources collection.
    /// Edge case: no resources requested.
    /// </summary>
    [Fact]
    public void Validate_WithEmptyResources_ShouldSucceed()
    {
        // Arrange
        var resources = Enumerable.Empty<Uri>();
        var scopes = new[] { "api1:read" };

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Empty(definitions);
    }

    /// <summary>
    /// Verifies validation with empty scopes collection.
    /// Resource should be included but with no scopes filtered.
    /// </summary>
    [Fact]
    public void Validate_WithEmptyScopes_ShouldReturnResourceWithNoScopes()
    {
        // Arrange
        var resources = new[] { new Uri("https://api1.example.com") };
        var scopes = Enumerable.Empty<string>();

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        var definition = Assert.Single(definitions);
        Assert.Equal(new Uri("https://api1.example.com"), definition.Resource);
        Assert.Empty(definition.Scopes);
    }

    /// <summary>
    /// Verifies validation with scopes not belonging to resource.
    /// Scopes should be filtered - only matching scopes included.
    /// </summary>
    [Fact]
    public void Validate_WithNonMatchingScopes_ShouldReturnEmptyScopes()
    {
        // Arrange
        var resources = new[] { new Uri("https://api1.example.com") };
        var scopes = new[] { "api2:admin" }; // Scope from different resource

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        var definition = Assert.Single(definitions);
        Assert.Equal(new Uri("https://api1.example.com"), definition.Resource);
        Assert.Empty(definition.Scopes); // No matching scopes
    }

    /// <summary>
    /// Verifies validation with query parameters in URI.
    /// Per RFC 8707, query component SHOULD NOT be included, but exceptions are allowed.
    /// </summary>
    [Fact]
    public void Validate_WithQueryParameters_ShouldValidate()
    {
        // Arrange
        var resourceWithQuery = new ResourceDefinition(
            new Uri("https://api.example.com?version=v1"),
            new ScopeDefinition("api:read"));

        var options = Options.Create(new OidcOptions { Resources = [resourceWithQuery] });
        var manager = new ResourceManager(options);

        var resources = new[] { new Uri("https://api.example.com?version=v1") };
        var scopes = new[] { "api:read" };

        // Act
        var result = manager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        var definition = Assert.Single(definitions);
        Assert.Equal("https://api.example.com/?version=v1", definition.Resource.AbsoluteUri);
    }

    /// <summary>
    /// Verifies first invalid resource stops validation.
    /// Validation fails fast on first error.
    /// </summary>
    [Fact]
    public void Validate_WithFirstResourceInvalid_ShouldFailImmediately()
    {
        // Arrange
        var resources = new[]
        {
            new Uri("https://unknown.example.com"), // Unknown
            new Uri("https://api1.example.com")     // Valid
        };
        var scopes = new[] { "api1:read" };

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.False(result);
        Assert.Null(definitions);
        Assert.NotNull(error);
        Assert.Equal("The requested resource is unknown", error);
    }

    /// <summary>
    /// Verifies duplicate resources are processed.
    /// Same resource may be requested multiple times.
    /// </summary>
    [Fact]
    public void Validate_WithDuplicateResources_ShouldProcessBoth()
    {
        // Arrange
        var resources = new[]
        {
            new Uri("https://api1.example.com"),
            new Uri("https://api1.example.com") // Duplicate
        };
        var scopes = new[] { "api1:read" };

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        Assert.Equal(2, definitions.Length);
        Assert.All(definitions, d => Assert.Equal(new Uri("https://api1.example.com"), d.Resource));
    }

    /// <summary>
    /// Verifies resource definition properties are preserved after filtering.
    /// Filtered resource should maintain all properties except modified scopes.
    /// </summary>
    [Fact]
    public void Validate_ShouldPreserveResourceDefinitionProperties()
    {
        // Arrange
        var resources = new[] { new Uri("https://api1.example.com") };
        var scopes = new[] { "api1:read" };

        // Act
        var result = _resourceManager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.NotNull(definitions);
        var definition = Assert.Single(definitions);

        Assert.Equal(new Uri("https://api1.example.com"), definition.Resource);
        Assert.Single(definition.Scopes);
        var scope = definition.Scopes[0];
        Assert.Equal("api1:read", scope.Scope);
        Assert.Single(scope.ClaimTypes);
        Assert.Equal("read_claim", scope.ClaimTypes[0]);
    }

    /// <summary>
    /// Verifies validation with URI containing port number.
    /// Port numbers should be handled correctly in resource matching.
    /// </summary>
    [Fact]
    public void Validate_WithPort_ShouldValidate()
    {
        // Arrange
        var resourceWithPort = new ResourceDefinition(
            new Uri("https://api.example.com:8443"),
            new ScopeDefinition("api:read"));

        var options = Options.Create(new OidcOptions { Resources = [resourceWithPort] });
        var manager = new ResourceManager(options);

        var resources = new[] { new Uri("https://api.example.com:8443") };
        var scopes = new[] { "api:read" };

        // Act
        var result = manager.Validate(resources, scopes, out var definitions, out var error);

        // Assert
        Assert.True(result);
        Assert.Null(error);
        Assert.NotNull(definitions);
        var definition = Assert.Single(definitions);
        Assert.Equal("https://api.example.com:8443/", definition.Resource.AbsoluteUri);
    }
}
