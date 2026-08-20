// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// In-memory implementation of backchannel authentication status notifier using TaskCompletionSource.
/// Suitable for single-server deployments or development environments.
/// </summary>
/// <remarks>
/// <para>
/// This implementation uses an in-memory dictionary of TaskCompletionSource objects to coordinate
/// between authentication completion and waiting token requests. When authentication status changes,
/// all waiting tasks are signaled via TaskCompletionSource.SetResult().
/// </para>
///
/// <para><strong>Characteristics:</strong></para>
/// <list type="bullet">
///   <item>Thread-safe using ConcurrentDictionary</item>
///   <item>Automatic cleanup of completed waiters</item>
///   <item>Supports multiple simultaneous waiters per auth_req_id</item>
///   <item>Memory efficient (only stores active waiters)</item>
///   <item>NOT suitable for multi-server deployments (notifications are local only)</item>
/// </list>
///
/// <para><strong>For Multi-Server Deployments:</strong></para>
/// <para>
/// Use a distributed implementation based on Redis Pub/Sub, SignalR backplane, or message queue.
/// </para>
/// </remarks>
public partial class InMemoryLongPollingService(
    ILogger<InMemoryLongPollingService> logger)
    : IBackChannelLongPollingService
{
    /// <summary>
    /// Dictionary mapping auth_req_id to the set of waiting TaskCompletionSource objects.
    /// Each auth_req_id can have multiple concurrent waiters (e.g., if client retries).
    /// A keyed set rather than a bag is used so a single timed-out waiter can remove exactly its
    /// own entry, which is what prevents unbounded growth for requests that expire without ever
    /// being notified.
    /// </summary>
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<TaskCompletionSource<bool>, byte>> _waiters = new();

    /// <summary>
    /// Waits for a status change notification for the specified authentication request.
    /// Uses TaskCompletionSource to efficiently wait without blocking threads.
    /// </summary>
    public async Task<bool> WaitForStatusChangeAsync(
        string authenticationRequestId,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        var tcs = new TaskCompletionSource<bool>();

        // Register this waiter
        var waiters = _waiters.GetOrAdd(
            authenticationRequestId,
            _ => new ConcurrentDictionary<TaskCompletionSource<bool>, byte>());
        waiters.TryAdd(tcs, 0);

        LogWaitingForStatusChange(authenticationRequestId.Sanitized(), timeout);

        try
        {
            // Create timeout task
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeout);

            // Wait for either notification or timeout
            var timeoutTask = Task.Delay(Timeout.InfiniteTimeSpan, cts.Token);
            var completedTask = await Task.WhenAny(tcs.Task, timeoutTask);

            if (completedTask == tcs.Task)
            {
                LogStatusChangeReceived(authenticationRequestId.Sanitized());
                return true;
            }

            LogWaitTimedOut(authenticationRequestId.Sanitized());
            return false;
        }
        catch (OperationCanceledException ex) when (LogCancellation(ex, authenticationRequestId))
        {
            // Filter logs without catching; the exception continues to propagate with the original stack trace.
            throw;
        }
        finally
        {
            // A signaled waiter has already completed, so this is a no-op for it; for a timed-out
            // or cancelled waiter it releases the still-pending task.
            tcs.TrySetCanceled(cancellationToken);

            // Remove this waiter so a request abandoned by the user - one that expires by storage
            // TTL without ever being notified - does not accumulate task-completion sources and
            // leak memory in this singleton.
            waiters.TryRemove(tcs, out _);

            // Drop the now-empty key. The reference-equality overload guarantees a set that a
            // concurrent waiter has just replaced under the same auth_req_id is never removed by
            // mistake. A newly arrived waiter that registers in the tiny window between IsEmpty and
            // TryRemove simply falls back to full-timeout latency for that one poll and then cleans
            // itself up - no leak, no missed final result, self-healing.
            if (waiters.IsEmpty)
            {
                _waiters.TryRemove(
                    new KeyValuePair<string, ConcurrentDictionary<TaskCompletionSource<bool>, byte>>(
                        authenticationRequestId, waiters));
            }
        }
    }

    // Exception-filter helper: logs cancellation details while letting the original exception propagate unchanged.
    private bool LogCancellation(OperationCanceledException ex, string authenticationRequestId)
    {
        LogWaitCancelled(ex, authenticationRequestId.Sanitized());
        return false;
    }

    /// <summary>
    /// Notifies all waiting requests that the authentication status has changed.
    /// Signals all TaskCompletionSource objects waiting for this auth_req_id.
    /// </summary>
    public Task NotifyStatusChangeAsync(
        string authenticationRequestId,
        BackChannelAuthenticationStatus newStatus)
    {
        if (!_waiters.TryRemove(authenticationRequestId, out var waiters))
        {
            // No one waiting - this is normal and expected
            LogNoWaiters(newStatus, authenticationRequestId.Sanitized());
            return Task.CompletedTask;
        }

        LogNotifyingWaiters(waiters.Count, newStatus, authenticationRequestId.Sanitized());

        // Signal all waiting tasks
        foreach (var waiter in waiters.Keys)
        {
            waiter.TrySetResult(true);
        }

        return Task.CompletedTask;
    }
}
