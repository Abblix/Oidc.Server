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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Unit tests for <see cref="PingModeValidator"/> verifying CIBA ping mode validation
/// as defined in the OpenID Connect CIBA specification Section 7.1.
/// Tests cover client_notification_token requirement and endpoint configuration validation.
/// </summary>
public class PingModeValidatorTests
{
    private const string ClientId = "ciba_client_123";
    private const string NotificationToken = "bearer_token_xyz";
    private readonly Uri _notificationEndpoint = new("https://client.example.com/ciba/notify");

    private readonly PingModeValidator _validator = new();

    /// <summary>
    /// Verifies that the validator returns null (success) for poll mode clients,
    /// allowing them to skip ping mode validation requirements.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PollMode_ReturnsNull()
    {
        // Arrange
        var context = new BackChannelAuthenticationValidationContext(
            new BackChannelAuthenticationRequest(),
            new ClientRequest())
        {
            ClientInfo = new ClientInfo(ClientId)
            {
                BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Poll,
            },
        };

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that the validator returns null (success) for push mode clients,
    /// allowing them to skip ping mode validation requirements.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PushMode_ReturnsNull()
    {
        // Arrange
        var context = new BackChannelAuthenticationValidationContext(
            new BackChannelAuthenticationRequest(),
            new ClientRequest())
        {
            ClientInfo = new ClientInfo(ClientId)
            {
                BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push,
            },
        };

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that ping mode clients with all required configuration pass validation.
    /// This includes client_notification_token parameter and backchannel_client_notification_endpoint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PingModeWithTokenAndEndpoint_ReturnsNull()
    {
        // Arrange
        var context = new BackChannelAuthenticationValidationContext(
            new BackChannelAuthenticationRequest
            {
                ClientNotificationToken = NotificationToken,
            },
            new ClientRequest())
        {
            ClientInfo = new ClientInfo(ClientId)
            {
                BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
                BackChannelClientNotificationEndpoint = _notificationEndpoint,
            },
        };

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that when a ping mode client does not provide client_notification_token,
    /// the validator returns an InvalidRequest error per CIBA spec Section 7.1.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PingModeWithoutToken_ReturnsInvalidRequestError()
    {
        // Arrange
        var context = new BackChannelAuthenticationValidationContext(
            new BackChannelAuthenticationRequest
            {
                ClientNotificationToken = null,
            },
            new ClientRequest())
        {
            ClientInfo = new ClientInfo(ClientId)
            {
                BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
                BackChannelClientNotificationEndpoint = _notificationEndpoint,
            },
        };

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("client_notification_token", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("required", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when a ping mode client does not have a registered notification endpoint,
    /// the validator returns an InvalidClient error per CIBA spec Section 5.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PingModeWithoutEndpoint_ReturnsInvalidClientError()
    {
        // Arrange
        var context = new BackChannelAuthenticationValidationContext(
            new BackChannelAuthenticationRequest
            {
                ClientNotificationToken = NotificationToken,
            },
            new ClientRequest())
        {
            ClientInfo = new ClientInfo(ClientId)
            {
                BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
                BackChannelClientNotificationEndpoint = null,
            },
        };

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClient, result.Error);
        Assert.Contains("backchannel_client_notification_endpoint", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not configured", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when client_notification_token is an empty string,
    /// the validator treats it as missing and returns an InvalidRequest error.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PingModeWithEmptyToken_ReturnsInvalidRequestError()
    {
        // Arrange
        var context = new BackChannelAuthenticationValidationContext(
            new BackChannelAuthenticationRequest
            {
                ClientNotificationToken = string.Empty,
            },
            new ClientRequest())
        {
            ClientInfo = new ClientInfo(ClientId)
            {
                BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
                BackChannelClientNotificationEndpoint = _notificationEndpoint,
            },
        };

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("client_notification_token", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies that when both token and endpoint are missing in ping mode,
    /// the validator returns an error for the missing token first (parameter validation before config validation).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PingModeWithoutTokenAndEndpoint_ReturnsInvalidRequestError()
    {
        // Arrange
        var context = new BackChannelAuthenticationValidationContext(
            new BackChannelAuthenticationRequest
            {
                ClientNotificationToken = null,
            },
            new ClientRequest())
        {
            ClientInfo = new ClientInfo(ClientId)
            {
                BackChannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping,
                BackChannelClientNotificationEndpoint = null,
            },
        };

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("client_notification_token", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }
}
