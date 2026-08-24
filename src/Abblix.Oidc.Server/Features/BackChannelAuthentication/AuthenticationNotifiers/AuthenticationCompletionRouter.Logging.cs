// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

partial class AuthenticationCompletionRouter
{
    [LoggerMessage(
        EventId = LogEvents.Device.AuthenticationCompletionRouter.ClientNotFound,
        Level = LogLevel.Error,
        Message = "Client not found for auth_req_id: {AuthReqId}, ClientId: {ClientId}")]
    private partial void LogClientNotFound(string AuthReqId, string ClientId);

    [LoggerMessage(
        EventId = LogEvents.Device.AuthenticationCompletionRouter.AuthenticatedUserNotTheOneRequested,
        Level = LogLevel.Warning,
        Message = "The end user authenticated for auth_req_id {AuthReqId} is not the one the request named, " +
                  "so it is refused. ClientId: {ClientId}")]
    private partial void LogAuthenticatedUserNotTheOneRequested(string AuthReqId, string ClientId);
}
