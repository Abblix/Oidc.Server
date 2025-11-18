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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="BackChannelAuthenticationValidator"/> verifying
/// CIBA (Client-Initiated Backchannel Authentication) configuration validation.
/// </summary>
public class BackChannelAuthenticationValidatorTests
{
    private readonly Mock<IJsonWebTokenValidator> _jwtValidator;
    private readonly BackChannelAuthenticationValidator _validator;

    public BackChannelAuthenticationValidatorTests()
    {
        _jwtValidator = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        _validator = new BackChannelAuthenticationValidator(_jwtValidator.Object);
    }

    private ClientRegistrationValidationContext CreateContext(
        string? tokenDeliveryMode = null,
        Uri? notificationEndpoint = null,
        string? signingAlg = null)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [new Uri("https://example.com/callback")],
            BackChannelTokenDeliveryMode = tokenDeliveryMode,
            BackChannelClientNotificationEndpoint = notificationEndpoint,
            BackChannelAuthenticationRequestSigningAlg = signingAlg
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Verifies validation succeeds when no CIBA configuration specified.
    /// Per OIDC CIBA, backchannel authentication is optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoBackChannelConfig_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext();

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with poll mode without notification endpoint.
    /// Per OIDC CIBA, poll mode does not require notification endpoint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PollModeWithoutEndpoint_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when poll mode specifies notification endpoint.
    /// Per OIDC CIBA, poll mode must not have notification endpoint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PollModeWithEndpoint_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
            notificationEndpoint: new Uri("https://example.com/notify"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("poll", result.ErrorDescription);
        Assert.Contains("Notification endpoint is invalid", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when ping mode lacks notification endpoint.
    /// Per OIDC CIBA, ping mode requires notification endpoint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PingModeWithoutEndpoint_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(tokenDeliveryMode: BackchannelTokenDeliveryModes.Ping);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("ping or push", result.ErrorDescription);
        Assert.Contains("required", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when ping mode with endpoint specified.
    /// Implementation currently only supports poll mode.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PingModeWithEndpoint_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Ping,
            notificationEndpoint: new Uri("https://example.com/notify"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("not supported", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when push mode lacks notification endpoint.
    /// Per OIDC CIBA, push mode requires notification endpoint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PushModeWithoutEndpoint_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(tokenDeliveryMode: BackchannelTokenDeliveryModes.Push);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("ping or push", result.ErrorDescription);
        Assert.Contains("required", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when push mode with endpoint specified.
    /// Implementation currently only supports poll mode.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PushModeWithEndpoint_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Push,
            notificationEndpoint: new Uri("https://example.com/notify"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("not supported", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies error with unsupported token delivery mode.
    /// Per OIDC CIBA, only poll, ping, and push are standard modes.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedDeliveryMode_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(tokenDeliveryMode: "custom-mode");

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("not supported", result.ErrorDescription);
        Assert.Contains("token delivery mode", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds with supported signing algorithm.
    /// Per OIDC CIBA, signing algorithm must be from supported set.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSupportedSigningAlg_ShouldReturnNull()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256, SigningAlgorithms.ES256]);

        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
            signingAlg: SigningAlgorithms.RS256);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when signing algorithm not supported.
    /// Per OIDC CIBA, only advertised algorithms are allowed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithUnsupportedSigningAlg_ShouldReturnError()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns([SigningAlgorithms.RS256]);

        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
            signingAlg: SigningAlgorithms.ES512);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("signing algorithm", result.ErrorDescription);
        Assert.Contains("not supported", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies validation succeeds when signing algorithm not specified.
    /// Per OIDC CIBA, signing algorithm is optional.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutSigningAlg_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies algorithm comparison is case-sensitive.
    /// Per JOSE, algorithm names are case-sensitive.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_SigningAlgCaseSensitive_ShouldReturnError()
    {
        // Arrange
        _jwtValidator
            .Setup(v => v.SigningAlgorithmsSupported)
            .Returns(["RS256"]);

        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
            signingAlg: "rs256"); // Different case

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies validation with empty string signing algorithm.
    /// Empty string should be treated as no value (not validated).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptySigningAlg_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Poll,
            signingAlg: string.Empty);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }
}
