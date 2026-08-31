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
    /// It reports the state it found and says the cause is unknown, rather than listing causes. A list is
    /// complete until the next one, and this seam has already grown one nobody would have listed: push's
    /// own refusal path removes the record after a configuration fault, so the operator most likely to
    /// read this line - one who has just fixed a client registration - is in a case no enumeration of
    /// answered, refused, expired or evicted covers. For the same reason the message no longer prescribes
    /// a recovery: that operator's end user was never asked. <c>Status</c> is null exactly when the record is not there, which is a
    /// value the field's own domain does not have to carry.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.AuthenticationCompletionHandler.NotPendingOnCompletion,
        Level = LogLevel.Error,
        Message = "auth_req_id {AuthReqId} was refused at completion. Only a pending request can be " +
                  "answered, and the stored record reads {Status}. A null there means no record was " +
                  "found, and this seam cannot tell why: absence has more causes than it can " +
                  "distinguish, including a completion that already ran and removed the record.")]
    private partial void LogNotPendingOnCompletion(string AuthReqId, string? Status);
}
