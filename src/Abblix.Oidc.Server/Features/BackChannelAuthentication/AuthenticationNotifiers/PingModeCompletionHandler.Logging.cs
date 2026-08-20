// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

partial class PingModeCompletionHandler
{
    [LoggerMessage(
        EventId = LogEvents.Device.PingModeCompletionHandler.SendingPingNotification,
        Level = LogLevel.Information,
        Message = "Sending ping notification for auth_req_id: {AuthReqId}")]
    private partial void LogSendingPingNotification(string AuthReqId);
}
