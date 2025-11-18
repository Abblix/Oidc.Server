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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="GrantTypeValidator"/> verifying grant type validation
/// per OAuth 2.0 and OpenID Connect specifications.
/// </summary>
public class GrantTypeValidatorTests
{
    private readonly GrantTypeValidator _validator = new();

    private ClientRegistrationValidationContext CreateContext(
        string[][] responseTypes,
        string[] grantTypes)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [new Uri("https://example.com/callback")],
            ResponseTypes = responseTypes,
            GrantTypes = grantTypes
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Verifies validation succeeds with default configuration.
    /// Per OIDC DCR, default is response_type=code with grant_type=authorization_code.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDefaultCodeFlow_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.Code]],
            grantTypes: [GrantTypes.AuthorizationCode]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with implicit flow.
    /// response_type=token requires grant_type=implicit.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithImplicitTokenFlow_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.Token]],
            grantTypes: [GrantTypes.Implicit]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with implicit ID token flow.
    /// response_type=id_token requires grant_type=implicit.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithImplicitIdTokenFlow_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.IdToken]],
            grantTypes: [GrantTypes.Implicit]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with hybrid flow.
    /// response_type="code id_token" requires both authorization_code and implicit.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHybridFlow_ShouldRequireBothGrantTypes()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.Code, ResponseTypes.IdToken]],
            grantTypes: [GrantTypes.AuthorizationCode, GrantTypes.Implicit]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when authorization_code grant type is missing.
    /// response_type=code requires grant_type=authorization_code.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCodeResponseButNoAuthCodeGrant_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.Code]],
            grantTypes: [GrantTypes.Implicit]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("authorization_code", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when implicit grant type is missing.
    /// response_type=token requires grant_type=implicit.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithTokenResponseButNoImplicitGrant_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.Token]],
            grantTypes: [GrantTypes.AuthorizationCode]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("implicit", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when id_token response lacks implicit grant.
    /// response_type=id_token requires grant_type=implicit.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithIdTokenResponseButNoImplicitGrant_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.IdToken]],
            grantTypes: [GrantTypes.AuthorizationCode]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("implicit", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when hybrid flow lacks authorization_code grant.
    /// response_type="code id_token" requires both authorization_code and implicit.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHybridFlowMissingAuthCodeGrant_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.Code, ResponseTypes.IdToken]],
            grantTypes: [GrantTypes.Implicit]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("authorization_code", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when hybrid flow lacks implicit grant.
    /// response_type="code token" requires both authorization_code and implicit.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHybridFlowMissingImplicitGrant_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.Code, ResponseTypes.Token]],
            grantTypes: [GrantTypes.AuthorizationCode]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("implicit", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when hybrid flow missing both required grants.
    /// response_type="code id_token" requires both grants.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHybridFlowMissingBothGrants_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.Code, ResponseTypes.IdToken]],
            grantTypes: []);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("authorization_code", result.ErrorDescription);
        Assert.Contains("implicit", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with additional grant types.
    /// Per OAuth 2.0, clients may have more grant types than required by response types.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAdditionalGrantTypes_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.Code]],
            grantTypes: [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken, GrantTypes.Ciba]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with multiple response types.
    /// Client may support multiple flows simultaneously.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleResponseTypes_ShouldRequireAllNecessaryGrants()
    {
        // Arrange
        var context = CreateContext(
            responseTypes:
            [
                [ResponseTypes.Code],
                [ResponseTypes.Token],
                [ResponseTypes.IdToken]
            ],
            grantTypes: [GrantTypes.AuthorizationCode, GrantTypes.Implicit]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error lists all missing grant types.
    /// Error message must clearly indicate what's required.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMultipleMissingGrants_ShouldListAll()
    {
        // Arrange
        var context = CreateContext(
            responseTypes:
            [
                [ResponseTypes.Code],
                [ResponseTypes.Token]
            ],
            grantTypes: []);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("authorization_code", result.ErrorDescription);
        Assert.Contains("implicit", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with complex hybrid flow.
    /// response_type="code id_token token" requires both grants.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithComplexHybridFlow_ShouldRequireBothGrants()
    {
        // Arrange
        var context = CreateContext(
            responseTypes: [[ResponseTypes.Code, ResponseTypes.IdToken, ResponseTypes.Token]],
            grantTypes: [GrantTypes.AuthorizationCode, GrantTypes.Implicit]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }
}
