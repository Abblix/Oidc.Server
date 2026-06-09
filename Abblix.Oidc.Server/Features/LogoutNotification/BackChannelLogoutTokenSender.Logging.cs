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

namespace Abblix.Oidc.Server.Features.LogoutNotification;

partial class BackChannelLogoutTokenSender
{
    [LoggerMessage(
        EventId = LogEvents.Device.BackChannelLogoutTokenSender.RequestSent,
        Level = LogLevel.Debug,
        Message = "The request with {@Parameters} was sent to {Uri}, the status code {StatusCode} was received")]
    private partial void LogRequestSent(KeyValuePair<string, string>[] Parameters, Uri Uri, HttpStatusCode StatusCode);

    [LoggerMessage(
        EventId = LogEvents.Device.BackChannelLogoutTokenSender.SendFailed,
        Level = LogLevel.Error,
        Message = "Failed to send logout token to {Uri}. Status code: {StatusCode}")]
    private partial void LogSendFailed(Uri Uri, HttpStatusCode StatusCode);
}
