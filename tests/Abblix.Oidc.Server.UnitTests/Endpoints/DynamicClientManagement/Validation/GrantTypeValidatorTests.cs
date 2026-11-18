// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

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
            RedirectUris = [TestConstants.DefaultRedirectUri],
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(GrantTypes.AuthorizationCode, result.ErrorDescription);
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(GrantTypes.Implicit, result.ErrorDescription);
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(GrantTypes.Implicit, result.ErrorDescription);
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(GrantTypes.AuthorizationCode, result.ErrorDescription);
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(GrantTypes.Implicit, result.ErrorDescription);
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(GrantTypes.AuthorizationCode, result.ErrorDescription);
        Assert.Contains(GrantTypes.Implicit, result.ErrorDescription);
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains(GrantTypes.AuthorizationCode, result.ErrorDescription);
        Assert.Contains(GrantTypes.Implicit, result.ErrorDescription);
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
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// The other direction of the RFC 7591 section 2.1 correspondence: a grant type the table pairs with a response
    /// type needs a response type carrying it, authorization_code the code and implicit a token, which OpenID Connect
    /// Dynamic Client Registration 1.0 section 2 extends to the id_token. A client registering the grant without it
    /// is in the inconsistent state the section has the server keep it from, by invalid_client_metadata.
    /// </summary>
    [Theory]
    [InlineData(new[] { GrantTypes.AuthorizationCode }, new string[0], GrantTypes.AuthorizationCode)]
    [InlineData(new[] { GrantTypes.Implicit }, new string[0], GrantTypes.Implicit)]
    [InlineData(new[] { GrantTypes.AuthorizationCode, GrantTypes.Implicit }, new[] { ResponseTypes.Code }, GrantTypes.Implicit)]
    [InlineData(new[] { GrantTypes.AuthorizationCode }, new[] { ResponseTypes.None }, GrantTypes.AuthorizationCode)]
    public async Task GrantTypeWithoutItsResponseType_IsInvalidClientMetadata(
        string[] grantTypes, string[] responseTypes, string unmatched)
    {
        var context = CreateContext(
            responseTypes: [.. responseTypes.Select(responseType => new[] { responseType })],
            grantTypes: grantTypes);

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(unmatched, result.ErrorDescription);
    }

    /// <summary>
    /// The control of the rows above: the table pairs no response type with the grants a client calls the token
    /// endpoint alone with, so a client registering only those and no response type is consistent.
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.ClientCredentials)]
    [InlineData(GrantTypes.RefreshToken)]
    [InlineData(GrantTypes.Ciba)]
    [InlineData(GrantTypes.DeviceAuthorization)]
    [InlineData(GrantTypes.JwtBearer)]
    public async Task GrantTypeWithNoResponseType_NeedsNone(string grantType)
    {
        var context = CreateContext(responseTypes: [], grantTypes: [grantType]);

        Assert.Null(await _validator.ValidateAsync(SingleIssuer.Tenant, context));
    }
}
