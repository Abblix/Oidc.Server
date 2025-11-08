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
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="ResourceValidator"/> verifying resource indicator validation per
/// RFC 8707. Tests focus on validator behavior with resource indicators. Note: Resource validation
/// logic is in ResourceManagerExtensions.Validate (extension method using TryGet).
/// </summary>
public class ResourceValidatorTests
{
    private const string ClientId = "client_123";
    private static readonly Uri Resource1 = new("https://api1.example.com");
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

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(
        Uri[]? resources = null,
        string[]? scopes = null)
    {
        var request = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = scopes ?? [Scopes.OpenId],
            Resources = resources,
        };

        var clientInfo = new ClientInfo(ClientId);

        return new AuthorizationValidationContext(request)
        {
            ClientInfo = clientInfo,
        };
    }

    /// <summary>
    /// Verifies that ValidateAsync succeeds when no resources specified.
    /// Per RFC 8707, resource parameter is OPTIONAL.
    /// Tests default behavior without resource indicators.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutResources_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(resources: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        _resourceManager.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies that ValidateAsync succeeds with empty resources array.
    /// Empty array is treated same as null - no resources to validate.
    /// Tests edge case handling.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyResourcesArray_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(resources: []);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        _resourceManager.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts valid resource indicators.
    /// Per RFC 8707, resource parameter contains URIs identifying target resources.
    /// Uses ResourceManagerExtensions.Validate which calls TryGet internally.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidResource_ShouldSucceed()
    {
        // Arrange
        var resources = new[] { Resource1 };
        var scopes = new[] { Scopes.OpenId, "read" };
        var resourceDefinition = new ResourceDefinition(Resource1, new ScopeDefinition("read"));

        _resourceManager
            .Setup(m => m.TryGet(Resource1, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = resourceDefinition;
                return true;
            }));

        var context = CreateContext(resources, scopes);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.Resources);
        Assert.Single(context.Resources);
        Assert.Equal(Resource1, context.Resources[0].Resource);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects unknown resource indicators.
    /// Per RFC 8707, unrecognized resources should be rejected.
    /// Critical security check preventing unauthorized resource access.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnknownResource_ShouldReturnError()
    {
        // Arrange
        var resources = new[] { UnknownResource };
        var scopes = new[] { Scopes.OpenId };

        _resourceManager
            .Setup(m => m.TryGet(UnknownResource, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = null;
                return false;
            }));

        var context = CreateContext(resources, scopes);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidTarget, result.Error);
        Assert.Contains("unknown", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that ValidateAsync returns InvalidTarget error code per RFC 8707.
    /// Per RFC 8707 Section 3, invalid_target error code indicates resource validation failure.
    /// Critical for proper error communication per specification.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnValidationFailure_ShouldReturnInvalidTargetError()
    {
        // Arrange
        var resources = new[] { UnknownResource };
        var scopes = new[] { Scopes.OpenId };

        _resourceManager
            .Setup(m => m.TryGet(UnknownResource, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = null;
                return false;
            }));

        var context = CreateContext(resources, scopes);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidTarget, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync populates context.Resources on success.
    /// Downstream processing relies on Resources being populated.
    /// Critical for resource-specific token issuance.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldPopulateResources()
    {
        // Arrange
        var resources = new[] { Resource1 };
        var scopes = new[] { Scopes.OpenId, "read" };
        var resourceDefinition = new ResourceDefinition(Resource1, new ScopeDefinition("read"));

        _resourceManager
            .Setup(m => m.TryGet(Resource1, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = resourceDefinition;
                return true;
            }));

        var context = CreateContext(resources, scopes);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.NotNull(context.Resources);
        Assert.NotEmpty(context.Resources);
    }

    /// <summary>
    /// Verifies that ValidateAsync calls IResourceManager.TryGet for each resource.
    /// Tests integration with resource manager for resource lookup.
    /// Important for proper resource validation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallTryGetForResource()
    {
        // Arrange
        var resources = new[] { Resource1 };
        var scopes = new[] { Scopes.OpenId, "read" };
        var resourceDefinition = new ResourceDefinition(Resource1, new ScopeDefinition("read"));

        _resourceManager
            .Setup(m => m.TryGet(Resource1, out It.Ref<ResourceDefinition?>.IsAny))
            .Returns(new TryGetCallback((Uri r, out ResourceDefinition? def) =>
            {
                def = resourceDefinition;
                return true;
            }));

        var context = CreateContext(resources, scopes);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _resourceManager.Verify(
            m => m.TryGet(Resource1, out It.Ref<ResourceDefinition?>.IsAny),
            Times.Once);
    }
}
