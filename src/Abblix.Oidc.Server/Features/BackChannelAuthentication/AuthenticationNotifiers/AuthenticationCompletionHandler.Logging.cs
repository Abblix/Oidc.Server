// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

partial class AuthenticationCompletionHandler
{
    [LoggerMessage(
        EventId = LogEvents.Device.AuthenticationCompletionHandler.MissingNotificationConfig,
        Level = LogLevel.Error,
        Message = "{ModeName} client missing notification endpoint or token. ClientId: {ClientId}, auth_req_id: {AuthReqId}, Endpoint: {Endpoint}, Token: {HasToken}")]
    private partial void LogMissingNotificationConfig(string ModeName, string ClientId, string AuthReqId, string Endpoint, bool HasToken);
}
