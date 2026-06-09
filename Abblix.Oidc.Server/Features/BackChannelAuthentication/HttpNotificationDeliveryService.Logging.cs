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
