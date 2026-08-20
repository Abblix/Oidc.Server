// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.EndSession;

partial class EndSessionRequestProcessor
{
    [LoggerMessage(
        EventId = LogEvents.Endpoints.EndSessionRequestProcessor.UserLoggedOut,
        Level = LogLevel.Debug,
        Message = "The user with subject={Subject} was logged out from session {Session}")]
    private partial void LogUserLoggedOut(string Subject, string Session);

    [LoggerMessage(
        EventId = LogEvents.Endpoints.EndSessionRequestProcessor.ClientNotificationFailed,
        Level = LogLevel.Error,
        Message = "Failed to deliver a logout notification to client {ClientId}; the user's logout still completes")]
    private partial void LogClientLogoutNotificationFailed(Exception exception, string ClientId);
}
