// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.LogoutNotification;

partial class BackChannelLogoutTokenSender
{
    [LoggerMessage(
        EventId = LogEvents.Device.BackChannelLogoutTokenSender.RequestSent,
        Level = LogLevel.Debug,
        Message = "The logout token {JwtId} was sent to {Uri}, the status code {StatusCode} was received")]
    private partial void LogRequestSent(Sanitized JwtId, Uri Uri, HttpStatusCode StatusCode);

    [LoggerMessage(
        EventId = LogEvents.Device.BackChannelLogoutTokenSender.SendFailed,
        Level = LogLevel.Error,
        Message = "Failed to send logout token to {Uri}. Status code: {StatusCode}")]
    private partial void LogSendFailed(Uri Uri, HttpStatusCode StatusCode);
}
