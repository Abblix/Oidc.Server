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

    [LoggerMessage(
        EventId = LogEvents.Device.AuthenticationCompletionHandler.AuthenticatedUserNotTheOneRequested,
        Level = LogLevel.Warning,
        Message = "The end user authenticated for auth_req_id {AuthReqId} is not the one the request named, " +
                  "so it is refused. ClientId: {ClientId}")]
    private partial void LogAuthenticatedUserNotTheOneRequested(string AuthReqId, string ClientId);

    /// <summary>
    /// The escaped TYPES, never the entries: an authorization_details entry carries whatever its type
    /// defines, which for the types this serves is payment and account data.
    /// </summary>
    [LoggerMessage(
        EventId = LogEvents.Device.AuthenticationCompletionHandler.GrantedAuthorizationDetailsExceedTheRequest,
        Level = LogLevel.Warning,
        Message = "The grant completing auth_req_id {AuthReqId} carries authorization_details the request " +
                  "never asked for, so it is refused. ClientId: {ClientId}, types: {EscapedTypes}")]
    private partial void LogGrantedAuthorizationDetailsExceedTheRequest(
        string AuthReqId, string ClientId, string EscapedTypes);
}
