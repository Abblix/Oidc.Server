// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

partial class HttpNotificationDeliveryService
{
    [LoggerMessage(
        EventId = LogEvents.Device.HttpNotificationDeliveryService.SendingNotification,
        Level = LogLevel.Information,
        Message = "Sending CIBA {Mode} notification to {Endpoint}")]
    private partial void LogSendingNotification(string Mode, Uri Endpoint);

    [LoggerMessage(
        EventId = LogEvents.Device.HttpNotificationDeliveryService.NotificationSucceeded,
        Level = LogLevel.Information,
        Message = "Successfully sent CIBA {Mode} notification")]
    private partial void LogNotificationSucceeded(string Mode);

    [LoggerMessage(
        EventId = LogEvents.Device.HttpNotificationDeliveryService.NotificationFailed,
        Level = LogLevel.Warning,
        Message = "Failed to send CIBA {Mode} notification. Status: {StatusCode}")]
    private partial void LogNotificationFailed(string Mode, HttpStatusCode StatusCode);

    [LoggerMessage(
        EventId = LogEvents.Device.HttpNotificationDeliveryService.NotificationError,
        Level = LogLevel.Error,
        Message = "Error sending CIBA {Mode} notification to {Endpoint}")]
    private partial void LogNotificationError(Exception ex, string Mode, Uri Endpoint);
}
