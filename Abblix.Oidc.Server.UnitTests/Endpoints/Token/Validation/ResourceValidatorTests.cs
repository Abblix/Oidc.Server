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
using System.Collections.Generic;
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
/// for token requests per OAuth 2.0 Resource Indicators specification.
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

    private static TokenValidationContext CreateContext(
        Uri[]? resources = null,
        string[]? scope = null)
    {
        var tokenRequest = new TokenRequest
        {
            Resources = resources,
            Scope = scope,
        };
        var clientRequest = new ClientRequest();
        return new TokenValidationContext(tokenRequest, clientRequest);
    }

    /// <summary>
    /// Verifies successful validation with valid resources.
    /// Per OAuth 2.0 Resource Indicators, resources must be validated.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidResources_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(
            resources: new[] { new Uri("https://api.example.com") },
            scope: new[] { "read", "write" });
        var resourceDefinitions = new[] { new ResourceDefinition(new Uri("https://api.example.com")) };

        _resourceManager
            .Setup(m => m.Validate(
                It.IsAny<IEnumerable<Uri>>(),
                It.IsAny<IEnumerable<string>>(),
                out It.Ref<ResourceDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ResourceManagerCallback((IEnumerable<Uri> res, IEnumerable<string> scope, out ResourceDefinition[] defs, out string? error) =>
            {
                defs = resourceDefinitions;
                error = null;
            }))
            .Returns(true);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Equal(resourceDefinitions, context.Resources);
    }

    private delegate void ResourceManagerCallback(
        IEnumerable<Uri> resources,
        IEnumerable<string> scope,
        out ResourceDefinition[] definitions,
        out string? errorDescription);

    /// <summary>
    /// Verifies error when resource validation fails.
    /// Per OAuth 2.0, invalid resources must be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenResourceValidationFails_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            resources: new[] { new Uri("https://invalid.example.com") },
            scope: new[] { "read" });

        _resourceManager
            .Setup(m => m.Validate(
                It.IsAny<IEnumerable<Uri>>(),
                It.IsAny<IEnumerable<string>>(),
                out It.Ref<ResourceDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ResourceManagerCallback((IEnumerable<Uri> res, IEnumerable<string> scope, out ResourceDefinition[] defs, out string? error) =>
            {
                defs = Array.Empty<ResourceDefinition>();
                error = "Resource not found";
            }))
            .Returns(false);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidTarget, error.Error);
        Assert.Contains("Resource not found", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies successful validation when no resources specified.
    /// Per OAuth 2.0, resources are optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutResources_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(resources: null, scope: new[] { "read" });

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
        var context = CreateContext(resources: Array.Empty<Uri>(), scope: new[] { "read" });

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        _resourceManager.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies resource manager receives correct parameters.
    /// Manager should receive resources and scope from request.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPassCorrectParametersToResourceManager()
    {
        // Arrange
        var resources = new[] { new Uri("https://api1.example.com"), new Uri("https://api2.example.com") };
        var scope = new[] { "read", "write", "admin" };
        var context = CreateContext(resources, scope);
        var resourceDefinitions = new[] { new ResourceDefinition(new Uri("https://api1.example.com")) };

        IEnumerable<Uri>? capturedResources = null;
        IEnumerable<string>? capturedScope = null;

        _resourceManager
            .Setup(m => m.Validate(
                It.IsAny<IEnumerable<Uri>>(),
                It.IsAny<IEnumerable<string>>(),
                out It.Ref<ResourceDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ResourceManagerCallback((IEnumerable<Uri> res, IEnumerable<string> scp, out ResourceDefinition[] defs, out string? error) =>
            {
                capturedResources = res;
                capturedScope = scp;
                defs = resourceDefinitions;
                error = null;
            }))
            .Returns(true);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Equal(resources, capturedResources);
        Assert.Equal(scope, capturedScope);
    }

    /// <summary>
    /// Verifies context.Resources is set correctly on success.
    /// Validated resource definitions should be assigned to context.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetResourcesInContext()
    {
        // Arrange
        var context = CreateContext(resources: new[] { new Uri("https://api.example.com") });
        var resourceDefinitions = new[]
        {
            new ResourceDefinition(new Uri("https://api.example.com")),
        };

        _resourceManager
            .Setup(m => m.Validate(
                It.IsAny<IEnumerable<Uri>>(),
                It.IsAny<IEnumerable<string>>(),
                out It.Ref<ResourceDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ResourceManagerCallback((IEnumerable<Uri> res, IEnumerable<string> scope, out ResourceDefinition[] defs, out string? error) =>
            {
                defs = resourceDefinitions;
                error = null;
            }))
            .Returns(true);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.Equal(resourceDefinitions, context.Resources);
        Assert.Equal(new Uri("https://api.example.com"), context.Resources[0].Resource);
    }

    /// <summary>
    /// Verifies multiple resources validation.
    /// Validator should handle multiple resource indicators.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleResources_ShouldValidateAll()
    {
        // Arrange
        var resources = new[] { new Uri("https://api1.example.com"), new Uri("https://api2.example.com"), new Uri("https://api3.example.com") };
        var context = CreateContext(resources);
        var resourceDefinitions = new[]
        {
            new ResourceDefinition(new Uri("https://api1.example.com")),
            new ResourceDefinition(new Uri("https://api2.example.com")),
            new ResourceDefinition(new Uri("https://api3.example.com")),
        };

        _resourceManager
            .Setup(m => m.Validate(
                It.IsAny<IEnumerable<Uri>>(),
                It.IsAny<IEnumerable<string>>(),
                out It.Ref<ResourceDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ResourceManagerCallback((IEnumerable<Uri> res, IEnumerable<string> scope, out ResourceDefinition[] defs, out string? error) =>
            {
                defs = resourceDefinitions;
                error = null;
            }))
            .Returns(true);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        Assert.Equal(3, context.Resources.Length);
    }

    /// <summary>
    /// Verifies error description is propagated from resource manager.
    /// Resource manager error messages should be included in response.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPropagateErrorDescription()
    {
        // Arrange
        var context = CreateContext(resources: new[] { new Uri("https://api.example.com") });
        var errorMessage = "Resource 'https://api.example.com' is not registered";

        _resourceManager
            .Setup(m => m.Validate(
                It.IsAny<IEnumerable<Uri>>(),
                It.IsAny<IEnumerable<string>>(),
                out It.Ref<ResourceDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ResourceManagerCallback((IEnumerable<Uri> res, IEnumerable<string> scope, out ResourceDefinition[] defs, out string? error) =>
            {
                defs = Array.Empty<ResourceDefinition>();
                error = errorMessage;
            }))
            .Returns(false);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(errorMessage, error.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation with null scope.
    /// Validator should handle requests without scope parameter.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullScope_ShouldWork()
    {
        // Arrange
        var context = CreateContext(resources: new[] { new Uri("https://api.example.com") }, scope: null);
        var resourceDefinitions = new[] { new ResourceDefinition(new Uri("https://api.example.com")) };

        _resourceManager
            .Setup(m => m.Validate(
                It.IsAny<IEnumerable<Uri>>(),
                It.IsAny<IEnumerable<string>>(),
                out It.Ref<ResourceDefinition[]>.IsAny,
                out It.Ref<string?>.IsAny))
            .Callback(new ResourceManagerCallback((IEnumerable<Uri> res, IEnumerable<string> scope, out ResourceDefinition[] defs, out string? error) =>
            {
                defs = resourceDefinitions;
                error = null;
            }))
            .Returns(true);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }
}
