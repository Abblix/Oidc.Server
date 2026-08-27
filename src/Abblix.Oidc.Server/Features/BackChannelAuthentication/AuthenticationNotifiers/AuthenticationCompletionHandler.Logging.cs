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
    /// Logged as well as thrown. The throw reaches the host writing the recovery; the log reaches the
    /// operator reading a live system, who sees the attempt whether or not the host caught it.
    /// </summary>
    /// <remarks>
    /// It reports the state it found and nothing about the cause. Absence in particular has more causes
    /// than this seam can tell apart, and the operator most likely to read this line is one who has just
    /// fixed a client registration - a message asserting a second completion would send them hunting for
    /// one that never happened. <c>Status</c> is null exactly when the record is not there, which is a
    /// value the field's own domain does not have to carry.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.AuthenticationCompletionHandler.NotPendingOnCompletion,
        Level = LogLevel.Error,
        Message = "auth_req_id {AuthReqId} was refused at completion: the stored record reads {Status}, " +
                  "or is absent when that is null, and only a pending request can be answered. It has " +
                  "been answered, refused or has expired; recovering means asking the end user again.")]
    private partial void LogNotPendingOnCompletion(string AuthReqId, string? Status);
}
