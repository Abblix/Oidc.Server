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
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Unit tests for <see cref="ResourceValidator"/> verifying CIBA resource validation
/// per RFC 8707 (Resource Indicators for OAuth 2.0).
/// </summary>
public class ResourceValidatorTests
{
    private readonly Mock<IResourceManager> _resourceManager;
    private readonly ResourceValidator _validator;

    public ResourceValidatorTests()
    {
        _resourceManager = new Mock<IResourceManager>(MockBehavior.Strict);
        _validator = new ResourceValidator(_resourceManager.Object);
    }

    private BackChannelAuthenticationValidationContext CreateContext(Uri[]? resources = null, string[]? scopes = null)
    {
        var request = new BackChannelAuthenticationRequest
        {
            Scope = scopes ?? ["openid"],
            Resources = resources
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        return new BackChannelAuthenticationValidationContext(request, clientRequest)
        {
            ClientInfo = new ClientInfo("test-client")
        };
    }

    /// <summary>
    /// Verifies validation succeeds when no resources are specified.
    /// Per RFC 8707, resource parameter is optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoResources_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(resources: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with empty resources array.
    /// Empty resources array should be treated as no resources.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyResourcesArray_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(resources: []);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with a single valid resource.
    /// Per RFC 8707, resource must be absolute URI without fragment.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidResource_ShouldReturnNull()
    {
        // Arrange
        var resourceUri = new Uri("https://api.example.com");
        var resourceDefinition = new ResourceDefinition(
            resourceUri,
            new ScopeDefinition("openid", Array.Empty<string>()));

        _resourceManager
            .Setup(rm => rm.TryGet(resourceUri, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri uri, out ResourceDefinition? def) =>
            {
                def = resourceDefinition;
                return true;
            }));

        var context = CreateContext(resources: [resourceUri]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.Resources);
        Assert.Single(context.Resources);
        Assert.Equal(resourceUri, context.Resources[0].Resource);
    }

    private delegate bool TryGetCallback(Uri uri, out ResourceDefinition? definition);

    /// <summary>
    /// Verifies error when resource is not absolute URI.
    /// Per RFC 8707, resource indicators must be absolute URIs.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithRelativeUri_ShouldReturnInvalidTarget()
    {
        // Arrange
        var relativeUri = new Uri("/api/resource", UriKind.Relative);
        var context = CreateContext(resources: [relativeUri]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidTarget, result.Error);
        Assert.Equal("The resource must be absolute URI", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when resource contains fragment.
    /// Per RFC 8707, resource indicators must not contain fragments.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFragment_ShouldReturnInvalidTarget()
    {
        // Arrange
        var uriWithFragment = new Uri("https://api.example.com#fragment");
        var context = CreateContext(resources: [uriWithFragment]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidTarget, result.Error);
        Assert.Equal("The requested resource must not contain fragment part", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when resource is unknown.
    /// Resource manager must recognize all requested resources.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnknownResource_ShouldReturnInvalidTarget()
    {
        // Arrange
        var unknownResource = new Uri("https://unknown.example.com");

        _resourceManager
            .Setup(rm => rm.TryGet(unknownResource, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri uri, out ResourceDefinition? def) =>
            {
                def = null;
                return false;
            }));

        var context = CreateContext(resources: [unknownResource]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidTarget, result.Error);
        Assert.Equal("The requested resource is unknown", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with multiple valid resources.
    /// Per RFC 8707, multiple resource indicators may be specified.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleValidResources_ShouldReturnNull()
    {
        // Arrange
        var resource1 = new Uri("https://api1.example.com");
        var resource2 = new Uri("https://api2.example.com");

        var definition1 = new ResourceDefinition(resource1, new ScopeDefinition("openid", Array.Empty<string>()));
        var definition2 = new ResourceDefinition(resource2, new ScopeDefinition("openid", Array.Empty<string>()));

        _resourceManager
            .Setup(rm => rm.TryGet(resource1, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri uri, out ResourceDefinition? def) =>
            {
                def = definition1;
                return true;
            }));

        _resourceManager
            .Setup(rm => rm.TryGet(resource2, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri uri, out ResourceDefinition? def) =>
            {
                def = definition2;
                return true;
            }));

        var context = CreateContext(resources: [resource1, resource2]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.Resources);
        Assert.Equal(2, context.Resources.Length);
    }

    /// <summary>
    /// Verifies scope filtering in resource validation.
    /// Resource definitions should only include requested scopes.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithScopeFiltering_ShouldFilterScopes()
    {
        // Arrange
        var resourceUri = new Uri("https://api.example.com");
        var resourceDefinition = new ResourceDefinition(
            resourceUri,
            new ScopeDefinition("openid", Array.Empty<string>()),
            new ScopeDefinition("profile", Array.Empty<string>()),
            new ScopeDefinition("email", Array.Empty<string>()));

        _resourceManager
            .Setup(rm => rm.TryGet(resourceUri, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri uri, out ResourceDefinition? def) =>
            {
                def = resourceDefinition;
                return true;
            }));

        var context = CreateContext(
            resources: [resourceUri],
            scopes: ["openid", "profile"]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.Resources);
        Assert.Single(context.Resources);
        Assert.Equal(2, context.Resources[0].Scopes.Length);
    }

    /// <summary>
    /// Verifies context.Resources is always set on successful validation.
    /// Downstream handlers depend on this value.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetResourcesOnContext()
    {
        // Arrange
        var resourceUri = new Uri("https://api.example.com");
        var resourceDefinition = new ResourceDefinition(resourceUri, new ScopeDefinition("openid", Array.Empty<string>()));

        _resourceManager
            .Setup(rm => rm.TryGet(resourceUri, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri uri, out ResourceDefinition? def) =>
            {
                def = resourceDefinition;
                return true;
            }));

        var context = CreateContext(resources: [resourceUri]);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(context.Resources);
        Assert.Single(context.Resources);
    }

    /// <summary>
    /// Verifies validation fails at first invalid resource.
    /// Error should be returned immediately without processing remaining resources.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMixedResources_ShouldFailAtFirstInvalid()
    {
        // Arrange
        var invalidResource = new Uri("/relative", UriKind.Relative);
        var validResource = new Uri("https://api1.example.com");

        var context = CreateContext(resources: [invalidResource, validResource]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidTarget, result.Error);
        // Should fail on first resource without checking second
    }
}
