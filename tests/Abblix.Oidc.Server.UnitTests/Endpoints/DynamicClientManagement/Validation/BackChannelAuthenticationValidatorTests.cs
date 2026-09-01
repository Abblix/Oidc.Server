// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

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
            RedirectUris = [TestConstants.DefaultRedirectUri],
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
    }

    /// <summary>
    /// Verifies validation succeeds with ping mode and a notification endpoint.
    /// Per CIBA Core 1.0 Section 4, backchannel_client_notification_endpoint is "REQUIRED if the token
    /// delivery mode is set to ping or push".
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PingModeWithEndpoint_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Ping,
            notificationEndpoint: new Uri("https://example.com/notify"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies error when the notification endpoint is not an HTTPS URL.
    /// CIBA Core 1.0 Section 4, on the registration metadata: "It MUST be an HTTPS URL." The TLS clause
    /// that usually travels with it is Section 9 and is not a property of the registered value, so
    /// nothing here can check it.
    /// </summary>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Ping)]
    [InlineData(BackchannelTokenDeliveryModes.Push)]
    public async Task ValidateAsync_NotificationEndpointNotHttps_ShouldReturnError(string deliveryMode)
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: deliveryMode,
            notificationEndpoint: new Uri("http://client.example.com/notify"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
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
    }

    /// <summary>
    /// Verifies validation succeeds with push mode and a notification endpoint.
    /// Per CIBA Core 1.0 Section 4, backchannel_client_notification_endpoint is "REQUIRED if the token
    /// delivery mode is set to ping or push".
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PushModeWithEndpoint_ShouldReturnNull()
    {
        // Arrange
        var context = CreateContext(
            tokenDeliveryMode: BackchannelTokenDeliveryModes.Push,
            notificationEndpoint: new Uri("https://example.com/notify"));

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
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
    }

    /// <summary>
    /// Verifies validation succeeds when signing algorithm not specified.
    /// Per OIDC CIBA, signing algorithm is optional.
    /// </summary>
    [Fact]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("SonarAnalyzer", "S4144",
        Justification = "Separate CIBA scenarios that happen to share identical setup; names document distinct spec requirements.")]
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
    /// <summary>
    /// A relative notification endpoint is refused, not faulted on.
    /// </summary>
    /// <remarks>
    /// The third site of one class, after a sector identifier document's entries and the registered
    /// redirect URIs: <see cref="Uri.Scheme"/>
    /// raises on a relative URI rather than returning anything, so a scheme comparison alone turns a
    /// registration that should be refused into a server fault. <c>[AbsoluteUri]</c> sits on the member
    /// and does not help - the form binder honours it and the JSON deserializer does not - which is
    /// exactly why the same shape kept arriving at different validators.
    /// </remarks>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Ping)]
    [InlineData(BackchannelTokenDeliveryModes.Push)]
    public async Task ValidateAsync_ARelativeNotificationEndpoint_IsRefusedRatherThanFaulting(string mode)
    {
        var context = CreateContext(mode, new Uri("/cb", UriKind.Relative));

        var result = await _validator.ValidateAsync(context);

        Assert.Equal(ErrorCodes.InvalidRequest, Assert.IsType<OidcError>(result).Error);
    }
}
