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
        EventId = LogEvents.Device.AuthenticationCompletionRouter.NothingToDeny,
        Level = LogLevel.Error,
        Message = "auth_req_id {AuthReqId} could not be denied: no record was found, so there was no client " +
                  "to route the denial to.")]
    private partial void LogNothingToDeny(string AuthReqId);
}
