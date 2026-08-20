// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

partial class InMemoryLongPollingService
{
    [LoggerMessage(
        EventId = LogEvents.Device.InMemoryLongPollingService.WaitingForStatusChange,
        Level = LogLevel.Debug,
        Message = "Long-polling request waiting for auth_req_id: {AuthReqId}, timeout: {Timeout}")]
    private partial void LogWaitingForStatusChange(string AuthReqId, TimeSpan Timeout);

    [LoggerMessage(
        EventId = LogEvents.Device.InMemoryLongPollingService.StatusChangeReceived,
        Level = LogLevel.Information,
        Message = "Long-polling request received status change notification for auth_req_id: {AuthReqId}")]
    private partial void LogStatusChangeReceived(string AuthReqId);

    [LoggerMessage(
        EventId = LogEvents.Device.InMemoryLongPollingService.WaitTimedOut,
        Level = LogLevel.Debug,
        Message = "Long-polling request timed out for auth_req_id: {AuthReqId}")]
    private partial void LogWaitTimedOut(string AuthReqId);

    [LoggerMessage(
        EventId = LogEvents.Device.InMemoryLongPollingService.WaitCancelled,
        Level = LogLevel.Debug,
        Message = "Long-polling request cancelled for auth_req_id: {AuthReqId}")]
    private partial void LogWaitCancelled(Exception ex, string AuthReqId);

    [LoggerMessage(
        EventId = LogEvents.Device.InMemoryLongPollingService.NoWaiters,
        Level = LogLevel.Debug,
        Message = "Status changed to {Status} for auth_req_id: {AuthReqId}, but no long-polling requests waiting")]
    private partial void LogNoWaiters(BackChannelAuthenticationStatus Status, string AuthReqId);

    [LoggerMessage(
        EventId = LogEvents.Device.InMemoryLongPollingService.NotifyingWaiters,
        Level = LogLevel.Information,
        Message = "Notifying {Count} long-polling request(s) of status change to {Status} for auth_req_id: {AuthReqId}")]
    private partial void LogNotifyingWaiters(int Count, BackChannelAuthenticationStatus Status, string AuthReqId);
}
