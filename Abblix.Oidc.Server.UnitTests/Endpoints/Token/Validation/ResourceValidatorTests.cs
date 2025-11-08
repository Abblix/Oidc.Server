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
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// Unit tests for <see cref="ResourceValidator"/> verifying resource validation
/// for token requests per OAuth 2.0 Resource Indicators specification (RFC 8707).
/// Note: Resource validation logic is in ResourceManagerExtensions.Validate (extension method using TryGet).
/// </summary>
public class ResourceValidatorTests
{
    private static readonly Uri Resource1 = new("https://api1.example.com");
    private static readonly Uri Resource2 = new("https://api2.example.com");
    private static readonly Uri UnknownResource = new("https://unknown.example.com");

    private readonly Mock<IResourceManager> _resourceManager;
    private readonly ResourceValidator _validator;

    // Delegate for mocking out parameter behavior
    private delegate bool TryGetCallback(
        Uri resource,
        out ResourceDefinition? definition);

    public ResourceValidatorTests()
    {
        _resourceManager = new Mock<IResourceManager>(MockBehavior.Strict);
        _validator = new ResourceValidator(_resourceManager.Object);
    }

    private static TokenValidationContext CreateContext(
        Uri[]? resources = null,
        string[]? scope = null)
    {
        var tokenRequest = new TokenRequest
        {
            Resources = resources,
            Scope = scope!,
        };
        var clientRequest = new ClientRequest();
        return new TokenValidationContext(tokenRequest, clientRequest);
    }

    /// <summary>
    /// Verifies successful validation when no resources specified.
    /// Per RFC 8707, resources are optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutResources_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(resources: null, scope: ["read"]);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        _resourceManager.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies successful validation with empty resources array.
    /// Empty array should be treated as no resources.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyResources_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(resources: [], scope: ["read"]);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        _resourceManager.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies successful validation with valid resource.
    /// Per RFC 8707, resources must be validated against resource manager.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidResource_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            resources: [Resource1],
            scope: ["read", "write"]);
        var resourceDefinition = new ResourceDefinition(Resource1, new ScopeDefinition("read"));

        _resourceManager
            .Setup(m => m.TryGet(Resource1, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = resourceDefinition;
                return true;
            }));

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.NotNull(context.Resources);
        Assert.Single(context.Resources);
        Assert.Equal(Resource1, context.Resources[0].Resource);
    }

    /// <summary>
    /// Verifies error when resource is not found.
    /// Per RFC 8707, unknown resources must be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnknownResource_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            resources: [UnknownResource],
            scope: ["read"]);

        _resourceManager
            .Setup(m => m.TryGet(UnknownResource, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = null;
                return false;
            }));

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidTarget, error.Error);
        Assert.Contains("unknown", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies correct error code per RFC 8707.
    /// Invalid resources should return invalid_target error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnValidationFailure_ShouldReturnInvalidTargetError()
    {
        // Arrange
        var context = CreateContext(
            resources: [UnknownResource],
            scope: ["read"]);

        _resourceManager
            .Setup(m => m.TryGet(UnknownResource, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = null;
                return false;
            }));

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidTarget, error.Error);
    }

    /// <summary>
    /// Verifies context.Resources is populated on success.
    /// Validated resource definitions should be assigned to context.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetResourcesInContext()
    {
        // Arrange
        var context = CreateContext(resources: [Resource1], scope: ["read"]);
        var resourceDefinition = new ResourceDefinition(Resource1);

        _resourceManager
            .Setup(m => m.TryGet(Resource1, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = resourceDefinition;
                return true;
            }));

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Equal(new[] { resourceDefinition }, context.Resources);
        Assert.Equal(Resource1, context.Resources[0].Resource);
    }

    /// <summary>
    /// Verifies multiple resources validation.
    /// Validator should handle multiple resource indicators.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleResources_ShouldValidateAll()
    {
        // Arrange
        var resources = new[] { Resource1, Resource2 };
        var context = CreateContext(resources, ["read", "write"]);
        var resourceDef1 = new ResourceDefinition(Resource1);
        var resourceDef2 = new ResourceDefinition(Resource2);

        _resourceManager
            .Setup(m => m.TryGet(Resource1, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = resourceDef1;
                return true;
            }));
        _resourceManager
            .Setup(m => m.TryGet(Resource2, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = resourceDef2;
                return true;
            }));

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Equal(2, context.Resources.Length);
    }

    /// <summary>
    /// Verifies resource manager is called for each resource.
    /// TryGet should be invoked once per resource.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallTryGetForEachResource()
    {
        // Arrange
        var resources = new[] { Resource1, Resource2 };
        var context = CreateContext(resources, ["read", "write"]);
        var resourceDef1 = new ResourceDefinition(Resource1);
        var resourceDef2 = new ResourceDefinition(Resource2);

        _resourceManager
            .Setup(m => m.TryGet(Resource1, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = resourceDef1;
                return true;
            }));
        _resourceManager
            .Setup(m => m.TryGet(Resource2, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = resourceDef2;
                return true;
            }));

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _resourceManager.Verify(
            m => m.TryGet(Resource1, out It.Ref<ResourceDefinition?>.IsAny),
            Times.Once);
        _resourceManager.Verify(
            m => m.TryGet(Resource2, out It.Ref<ResourceDefinition?>.IsAny),
            Times.Once);
    }

    /// <summary>
    /// Verifies validation with empty scope.
    /// Validator should handle requests with empty scope array.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyScope_ShouldWork()
    {
        // Arrange
        var context = CreateContext(resources: [Resource1], scope: []);
        var resourceDefinition = new ResourceDefinition(Resource1);

        _resourceManager
            .Setup(m => m.TryGet(Resource1, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = resourceDefinition;
                return true;
            }));

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }
}
