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
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="TokenEndpointAuthMethodValidator"/> verifying
/// token endpoint authentication method validation per OIDC specifications.
/// </summary>
public class TokenEndpointAuthMethodValidatorTests
{
    private readonly Mock<IClientAuthenticator> _clientAuthenticator;
    private readonly TokenEndpointAuthMethodValidator _validator;

    public TokenEndpointAuthMethodValidatorTests()
    {
        _clientAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        _validator = new TokenEndpointAuthMethodValidator(_clientAuthenticator.Object);
    }

    private ClientRegistrationValidationContext CreateContext(string? tokenEndpointAuthMethod)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
            TokenEndpointAuthMethod = tokenEndpointAuthMethod!
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Verifies validation succeeds when auth method is not specified.
    /// Per OIDC DCR, token_endpoint_auth_method has a default value.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoAuthMethod_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(tokenEndpointAuthMethod: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds when auth method is empty string.
    /// Empty string is treated as no value specified.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyAuthMethod_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(tokenEndpointAuthMethod: string.Empty);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with supported auth method.
    /// Per OIDC DCR, client_secret_basic is a standard method.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedMethod_ShouldReturnNull()
    {
        // Arrange
        _clientAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.ClientSecretBasic, ClientAuthenticationMethods.ClientSecretPost]);

        var context = CreateContext(tokenEndpointAuthMethod: ClientAuthenticationMethods.ClientSecretBasic);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when auth method is not supported.
    /// Per OIDC DCR, only advertised methods are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedMethod_ShouldReturnError()
    {
        // Arrange
        _clientAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.ClientSecretBasic]);

        var context = CreateContext(tokenEndpointAuthMethod: ClientAuthenticationMethods.PrivateKeyJwt);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("not supported", result.ErrorDescription);
        Assert.Contains(ClientAuthenticationMethods.PrivateKeyJwt, result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation is case-sensitive.
    /// Per OAuth 2.0, authentication methods are case-sensitive.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentCase_ShouldReturnError()
    {
        // Arrange
        _clientAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns(["client_secret_basic"]);

        var context = CreateContext(tokenEndpointAuthMethod: "Client_Secret_Basic");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies validation succeeds with client_secret_post.
    /// Per OIDC Core, client_secret_post is a standard method.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithClientSecretPost_ShouldReturnNull()
    {
        // Arrange
        _clientAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.ClientSecretPost]);

        var context = CreateContext(tokenEndpointAuthMethod: ClientAuthenticationMethods.ClientSecretPost);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with private_key_jwt.
    /// Per OIDC Core, private_key_jwt is a standard asymmetric method.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithPrivateKeyJwt_ShouldReturnNull()
    {
        // Arrange
        _clientAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.PrivateKeyJwt]);

        var context = CreateContext(tokenEndpointAuthMethod: ClientAuthenticationMethods.PrivateKeyJwt);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with client_secret_jwt.
    /// Per OIDC Core, client_secret_jwt is a standard symmetric method.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithClientSecretJwt_ShouldReturnNull()
    {
        // Arrange
        _clientAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.ClientSecretJwt]);

        var context = CreateContext(tokenEndpointAuthMethod: ClientAuthenticationMethods.ClientSecretJwt);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with none method.
    /// Per OAuth 2.0, public clients use "none" for authentication.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoneMethod_ShouldReturnNull()
    {
        // Arrange
        _clientAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.None]);

        var context = CreateContext(tokenEndpointAuthMethod: ClientAuthenticationMethods.None);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds when method is in list of multiple supported methods.
    /// Providers may support multiple authentication methods.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMethodInMultipleSupportedMethods_ShouldReturnNull()
    {
        // Arrange
        _clientAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([
                ClientAuthenticationMethods.None,
                ClientAuthenticationMethods.ClientSecretBasic,
                ClientAuthenticationMethods.ClientSecretPost,
                ClientAuthenticationMethods.ClientSecretJwt,
                ClientAuthenticationMethods.PrivateKeyJwt
            ]);

        var context = CreateContext(tokenEndpointAuthMethod: ClientAuthenticationMethods.ClientSecretPost);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error with custom/unknown authentication method.
    /// Only OIDC standard methods or provider-specific advertised methods allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomMethod_ShouldReturnError()
    {
        // Arrange
        _clientAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.ClientSecretBasic]);

        var context = CreateContext(tokenEndpointAuthMethod: "custom_auth_method");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("custom_auth_method", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validator checks provider's supported methods.
    /// Ensures proper delegation to client authenticator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCheckClientAuthenticator()
    {
        // Arrange
        _clientAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.ClientSecretBasic]);

        var context = CreateContext(tokenEndpointAuthMethod: ClientAuthenticationMethods.ClientSecretBasic);

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        _clientAuthenticator.Verify(a => a.ClientAuthenticationMethodsSupported, Times.Once);
    }

    /// <summary>
    /// Verifies error message includes the unsupported method name.
    /// Error messages must be informative for debugging.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedMethod_ShouldIncludeMethodInError()
    {
        // Arrange
        _clientAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.None]);

        var context = CreateContext(tokenEndpointAuthMethod: "unsupported_method");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("unsupported_method", result.ErrorDescription);
    }
}
