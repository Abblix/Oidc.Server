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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ResourceIndicators;

/// <summary>
/// Unit tests for <see cref="ResourceManager"/> verifying resource registration and retrieval
/// per OAuth 2.0 RFC 8707 (Resource Indicators for OAuth 2.0).
/// Tests cover resource initialization, lookup, and edge cases.
/// </summary>
public class ResourceManagerTests
{
    /// <summary>
    /// Verifies ResourceManager with no configured resources.
    /// Edge case: empty resource configuration.
    /// </summary>
    [Fact]
    public void Constructor_WithNoResources_ShouldCreateEmptyManager()
    {
        // Arrange
        var options = Options.Create(new OidcOptions());

        // Act
        var manager = new ResourceManager(options);

        // Assert
        var testUri = new Uri("https://api.example.com");
        Assert.False(manager.TryGet(testUri, out var definition));
        Assert.Null(definition);
    }

    /// <summary>
    /// Verifies single resource registration.
    /// Per RFC 8707, resources are identified by absolute URIs.
    /// </summary>
    [Fact]
    public void Constructor_WithSingleResource_ShouldRegisterResource()
    {
        // Arrange
        var resourceUri = new Uri("https://api.example.com");
        var resource = new ResourceDefinition(resourceUri,
            new ScopeDefinition("read", "read_claim"),
            new ScopeDefinition("write", "write_claim"));

        var options = Options.Create(new OidcOptions
        {
            Resources = [resource]
        });

        // Act
        var manager = new ResourceManager(options);

        // Assert
        Assert.True(manager.TryGet(resourceUri, out var retrieved));
        Assert.NotNull(retrieved);
        Assert.Equal(resourceUri, retrieved.Resource);
        Assert.Equal(2, retrieved.Scopes.Length);
    }

    /// <summary>
    /// Verifies multiple resources registration.
    /// Authorization servers typically protect multiple resources.
    /// </summary>
    [Fact]
    public void Constructor_WithMultipleResources_ShouldRegisterAll()
    {
        // Arrange
        var resource1 = new ResourceDefinition(
            new Uri("https://api1.example.com"),
            new ScopeDefinition("api1:read"));

        var resource2 = new ResourceDefinition(
            new Uri("https://api2.example.com"),
            new ScopeDefinition("api2:write"));

        var resource3 = new ResourceDefinition(
            new Uri("https://api3.example.com"),
            new ScopeDefinition("api3:admin"));

        var options = Options.Create(new OidcOptions
        {
            Resources = [resource1, resource2, resource3]
        });

        // Act
        var manager = new ResourceManager(options);

        // Assert
        Assert.True(manager.TryGet(new Uri("https://api1.example.com"), out _));
        Assert.True(manager.TryGet(new Uri("https://api2.example.com"), out _));
        Assert.True(manager.TryGet(new Uri("https://api3.example.com"), out _));
    }

    /// <summary>
    /// Verifies TryGet returns false for unregistered resource.
    /// Per RFC 8707, only registered resources should be recognized.
    /// </summary>
    [Fact]
    public void TryGet_WithUnregisteredResource_ShouldReturnFalse()
    {
        // Arrange
        var registeredUri = new Uri("https://api.example.com");
        var unregisteredUri = new Uri("https://unknown.example.com");

        var resource = new ResourceDefinition(registeredUri,
            new ScopeDefinition("read"));

        var options = Options.Create(new OidcOptions { Resources = [resource] });
        var manager = new ResourceManager(options);

        // Act
        var result = manager.TryGet(unregisteredUri, out var definition);

        // Assert
        Assert.False(result);
        Assert.Null(definition);
    }

    /// <summary>
    /// Verifies URI comparison is exact (case-sensitive host, path, etc.).
    /// Per RFC 3986, URI comparison is case-sensitive except for scheme and host.
    /// </summary>
    [Fact]
    public void TryGet_WithDifferentCase_ShouldRespectUriEquality()
    {
        // Arrange
        var resourceUri = new Uri("https://api.example.com/v1");
        var resource = new ResourceDefinition(resourceUri, new ScopeDefinition("read"));

        var options = Options.Create(new OidcOptions { Resources = [resource] });
        var manager = new ResourceManager(options);

        // Act & Assert - Scheme and host are case-insensitive
        Assert.True(manager.TryGet(new Uri("HTTPS://API.EXAMPLE.COM/v1"), out _));

        // Act & Assert - Path is case-sensitive
        Assert.False(manager.TryGet(new Uri("https://api.example.com/V1"), out _));
    }

    /// <summary>
    /// Verifies resource with multiple scopes.
    /// A single resource typically defines multiple scopes.
    /// </summary>
    [Fact]
    public void TryGet_ShouldPreserveAllScopes()
    {
        // Arrange
        var resourceUri = new Uri("https://api.example.com");
        var resource = new ResourceDefinition(resourceUri,
            new ScopeDefinition("read", "read_claim"),
            new ScopeDefinition("write", "write_claim"),
            new ScopeDefinition("delete", "delete_claim"));

        var options = Options.Create(new OidcOptions { Resources = [resource] });
        var manager = new ResourceManager(options);

        // Act
        var result = manager.TryGet(resourceUri, out var definition);

        // Assert
        Assert.True(result);
        Assert.NotNull(definition);
        Assert.Equal(3, definition.Scopes.Length);
        Assert.Contains(definition.Scopes, s => s.Scope == "read");
        Assert.Contains(definition.Scopes, s => s.Scope == "write");
        Assert.Contains(definition.Scopes, s => s.Scope == "delete");
    }

    /// <summary>
    /// Verifies resource with query parameters.
    /// Per RFC 8707, resource URIs may contain query parameters.
    /// </summary>
    [Fact]
    public void TryGet_WithQueryParameters_ShouldMatchExactly()
    {
        // Arrange
        var resourceWithQuery = new Uri("https://api.example.com?version=v1");
        var resourceWithoutQuery = new Uri("https://api.example.com");

        var resource = new ResourceDefinition(resourceWithQuery, new ScopeDefinition("read"));

        var options = Options.Create(new OidcOptions { Resources = [resource] });
        var manager = new ResourceManager(options);

        // Act & Assert - Must match exactly including query
        Assert.True(manager.TryGet(resourceWithQuery, out _));
        Assert.False(manager.TryGet(resourceWithoutQuery, out _));
    }

    /// <summary>
    /// Verifies resource with port number.
    /// Per RFC 8707, resource URIs may include port numbers.
    /// </summary>
    [Fact]
    public void TryGet_WithPort_ShouldMatchExactly()
    {
        // Arrange
        var resourceWithPort = new Uri("https://api.example.com:8443");
        var resourceDefaultPort = new Uri("https://api.example.com");

        var resource = new ResourceDefinition(resourceWithPort, new ScopeDefinition("read"));

        var options = Options.Create(new OidcOptions { Resources = [resource] });
        var manager = new ResourceManager(options);

        // Act & Assert
        Assert.True(manager.TryGet(resourceWithPort, out _));
        Assert.False(manager.TryGet(resourceDefaultPort, out _));
    }

    /// <summary>
    /// Verifies null resources configuration is handled.
    /// Edge case: null configuration.
    /// </summary>
    [Fact]
    public void Constructor_WithNullResources_ShouldCreateEmptyManager()
    {
        // Arrange
        var options = Options.Create(new OidcOptions { Resources = null });

        // Act
        var manager = new ResourceManager(options);

        // Assert
        Assert.False(manager.TryGet(new Uri("https://api.example.com"), out _));
    }

    /// <summary>
    /// Verifies empty resources array is handled.
    /// Edge case: empty array.
    /// </summary>
    [Fact]
    public void Constructor_WithEmptyResourcesArray_ShouldCreateEmptyManager()
    {
        // Arrange
        var options = Options.Create(new OidcOptions { Resources = [] });

        // Act
        var manager = new ResourceManager(options);

        // Assert
        Assert.False(manager.TryGet(new Uri("https://api.example.com"), out _));
    }

    /// <summary>
    /// Verifies resource with trailing slash on path.
    /// Per RFC 3986, URIs with/without trailing slash on paths are different.
    /// Note: Domain-only URIs normalize trailing slashes, so test uses path.
    /// </summary>
    [Fact]
    public void TryGet_WithTrailingSlash_ShouldMatchExactly()
    {
        // Arrange
        var resourceWithSlash = new Uri("https://api.example.com/v1/");
        var resourceWithoutSlash = new Uri("https://api.example.com/v1");

        var resource = new ResourceDefinition(resourceWithSlash, new ScopeDefinition("read"));

        var options = Options.Create(new OidcOptions { Resources = [resource] });
        var manager = new ResourceManager(options);

        // Act & Assert
        Assert.True(manager.TryGet(resourceWithSlash, out _));
        Assert.False(manager.TryGet(resourceWithoutSlash, out _));
    }

    /// <summary>
    /// Verifies resource with path components.
    /// Per RFC 8707, resource URIs may include path components.
    /// </summary>
    [Fact]
    public void TryGet_WithPath_ShouldMatchExactly()
    {
        // Arrange
        var resource1 = new ResourceDefinition(
            new Uri("https://api.example.com/v1"),
            new ScopeDefinition("read"));

        var resource2 = new ResourceDefinition(
            new Uri("https://api.example.com/v2"),
            new ScopeDefinition("read"));

        var options = Options.Create(new OidcOptions { Resources = [resource1, resource2] });
        var manager = new ResourceManager(options);

        // Act & Assert
        Assert.True(manager.TryGet(new Uri("https://api.example.com/v1"), out var def1));
        Assert.True(manager.TryGet(new Uri("https://api.example.com/v2"), out var def2));
        Assert.NotSame(def1, def2);
    }

    /// <summary>
    /// Verifies resource definition properties are preserved.
    /// ResourceDefinition should maintain all its properties.
    /// </summary>
    [Fact]
    public void TryGet_ShouldPreserveResourceDefinitionProperties()
    {
        // Arrange
        var resourceUri = new Uri("https://api.example.com");
        var scopes = new[]
        {
            new ScopeDefinition("read", "read_claim1", "read_claim2"),
            new ScopeDefinition("write", "write_claim1")
        };

        var resource = new ResourceDefinition(resourceUri, scopes);

        var options = Options.Create(new OidcOptions { Resources = [resource] });
        var manager = new ResourceManager(options);

        // Act
        var result = manager.TryGet(resourceUri, out var definition);

        // Assert
        Assert.True(result);
        Assert.NotNull(definition);
        Assert.Equal(resourceUri, definition.Resource);

        var readScope = definition.Scopes[0];
        Assert.Equal("read", readScope.Scope);
        Assert.Equal(2, readScope.ClaimTypes.Length);
        Assert.Contains("read_claim1", readScope.ClaimTypes);
        Assert.Contains("read_claim2", readScope.ClaimTypes);

        var writeScope = definition.Scopes[1];
        Assert.Equal("write", writeScope.Scope);
        Assert.Single(writeScope.ClaimTypes);
        Assert.Contains("write_claim1", writeScope.ClaimTypes);
    }
}
