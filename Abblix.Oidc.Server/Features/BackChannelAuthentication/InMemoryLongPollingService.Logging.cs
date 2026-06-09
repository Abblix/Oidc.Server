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
