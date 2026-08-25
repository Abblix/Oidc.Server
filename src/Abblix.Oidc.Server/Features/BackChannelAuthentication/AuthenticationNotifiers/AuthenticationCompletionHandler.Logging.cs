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

    /// <summary>
    /// The validator's own words, which the client never sees.
    /// </summary>
    /// <remarks>
    /// A refusal here names a HOST-side defect: the end user approved something the deployment will not
    /// issue, so whoever has to fix it is an operator rather than the client. The client is told nothing
    /// at all in push mode, since the outcome travels to it through a notification endpoint this server
    /// sends no error payload to, and in poll and ping it learns only that the request was denied.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.AuthenticationCompletionHandler.GrantedAuthorizationDetailsRefused,
        Level = LogLevel.Warning,
        Message = "The per-type validators will not issue the authorization_details completing " +
                  "auth_req_id {AuthReqId}, so it is refused. ClientId: {ClientId}, reason: {Reason}")]
    private partial void LogGrantedAuthorizationDetailsRefused(
        string AuthReqId, string ClientId, string Reason);
}
