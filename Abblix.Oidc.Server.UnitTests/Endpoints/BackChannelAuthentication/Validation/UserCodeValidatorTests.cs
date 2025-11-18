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

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Unit tests for <see cref="UserCodeValidator"/> verifying CIBA user_code parameter validation
/// per OpenID Connect CIBA specification Section 7.1.
/// </summary>
public class UserCodeValidatorTests
{
    private readonly Mock<IOptions<OidcOptions>> _options;
    private readonly OidcOptions _oidcOptions;
    private readonly UserCodeValidator _validator;

    public UserCodeValidatorTests()
    {
        _options = new Mock<IOptions<OidcOptions>>(MockBehavior.Strict);
        _oidcOptions = new OidcOptions
        {
            BackChannelAuthentication = new BackChannelAuthenticationOptions
            {
                UserCodeParameterSupported = false
            }
        };

        _options.Setup(o => o.Value).Returns(_oidcOptions);
        _validator = new UserCodeValidator(_options.Object);
    }

    private BackChannelAuthenticationValidationContext CreateContext(
        string? userCode = null,
        bool providerSupportsUserCode = false,
        bool clientRequiresUserCode = false)
    {
        _oidcOptions.BackChannelAuthentication.UserCodeParameterSupported = providerSupportsUserCode;

        var request = new BackChannelAuthenticationRequest
        {
            Scope = ["openid"],
            UserCode = userCode
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        return new BackChannelAuthenticationValidationContext(request, clientRequest)
        {
            ClientInfo = new ClientInfo("test-client")
            {
                BackChannelUserCodeParameter = clientRequiresUserCode
            }
        };
    }

    /// <summary>
    /// Verifies validation succeeds when user_code is not required by provider.
    /// Per CIBA specification, user_code is optional and depends on provider configuration.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ProviderDoesNotSupportUserCode_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            userCode: null,
            providerSupportsUserCode: false,
            clientRequiresUserCode: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds when user_code is not required by client.
    /// Client must explicitly request user_code support.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ClientDoesNotRequireUserCode_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            userCode: null,
            providerSupportsUserCode: true,
            clientRequiresUserCode: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds when neither provider nor client support user_code.
    /// Default CIBA configuration does not require user_code.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NeitherSupportUserCode_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            userCode: null,
            providerSupportsUserCode: false,
            clientRequiresUserCode: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds when user_code is required and provided.
    /// Per CIBA specification, when user_code is enabled, it must be present.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_UserCodeRequiredAndProvided_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            userCode: "ABC123",
            providerSupportsUserCode: true,
            clientRequiresUserCode: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when user_code is required but missing.
    /// Per CIBA specification, missing required parameters must return error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_UserCodeRequiredButMissing_ShouldReturnMissingUserCode()
    {
        // Arrange
        var context = CreateContext(
            userCode: null,
            providerSupportsUserCode: true,
            clientRequiresUserCode: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.MissingUserCode, result.Error);
        Assert.Equal("The UserCode parameter is missing.", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when user_code is required but empty string.
    /// Empty string is treated the same as null/missing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_UserCodeRequiredButEmpty_ShouldReturnMissingUserCode()
    {
        // Arrange
        var context = CreateContext(
            userCode: string.Empty,
            providerSupportsUserCode: true,
            clientRequiresUserCode: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.MissingUserCode, result.Error);
    }

    /// <summary>
    /// Verifies validation succeeds when user_code is required and whitespace provided.
    /// Validator only checks for null or empty, not whitespace.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_UserCodeRequiredWithWhitespace_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            userCode: "   ",
            providerSupportsUserCode: true,
            clientRequiresUserCode: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds when user_code is not required but provided anyway.
    /// Clients can provide user_code even when not required.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_UserCodeNotRequiredButProvided_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            userCode: "ABC123",
            providerSupportsUserCode: false,
            clientRequiresUserCode: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation requires BOTH provider support AND client requirement.
    /// If provider doesn't support, client requirement is ignored.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnlyProviderSupports_ShouldNotRequire()
    {
        // Arrange
        var context = CreateContext(
            userCode: null,
            providerSupportsUserCode: true,
            clientRequiresUserCode: false);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result); // Should pass because client doesn't require
    }

    /// <summary>
    /// Verifies validation requires BOTH provider support AND client requirement.
    /// If client requires but provider doesn't support, not required.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnlyClientRequires_ShouldNotRequire()
    {
        // Arrange
        var context = CreateContext(
            userCode: null,
            providerSupportsUserCode: false,
            clientRequiresUserCode: true);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result); // Should pass because provider doesn't support
    }
}
