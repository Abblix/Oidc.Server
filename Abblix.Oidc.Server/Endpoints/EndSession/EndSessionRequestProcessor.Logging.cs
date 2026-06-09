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
