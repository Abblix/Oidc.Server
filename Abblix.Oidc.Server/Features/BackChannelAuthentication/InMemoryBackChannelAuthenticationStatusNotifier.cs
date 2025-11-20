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

using System.Collections.Concurrent;
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
/// Example with Redis:
/// </para>
/// <code>
/// public class RedisBackChannelAuthenticationStatusNotifier : IBackChannelAuthenticationStatusNotifier
/// {
///     private readonly IConnectionMultiplexer _redis;
///
///     public async Task&lt;bool&gt; WaitForStatusChangeAsync(string authReqId, TimeSpan timeout, CancellationToken ct)
///     {
///         var subscriber = _redis.GetSubscriber();
///         var tcs = new TaskCompletionSource&lt;bool&gt;();
///
///         await subscriber.SubscribeAsync($"ciba:{authReqId}", (channel, value) =&gt; tcs.TrySetResult(true));
///
///         var timeoutTask = Task.Delay(timeout, ct);
///         var completedTask = await Task.WhenAny(tcs.Task, timeoutTask);
///
///         return completedTask == tcs.Task;
///     }
///
///     public Task NotifyStatusChangeAsync(string authReqId, BackChannelAuthenticationStatus status)
///     {
///         var subscriber = _redis.GetSubscriber();
///         return subscriber.PublishAsync($"ciba:{authReqId}", status.ToString());
///     }
/// }
/// </code>
/// </remarks>
public class InMemoryBackChannelAuthenticationStatusNotifier(
    ILogger<InMemoryBackChannelAuthenticationStatusNotifier> logger)
    : IBackChannelAuthenticationStatusNotifier
{
    /// <summary>
    /// Dictionary mapping auth_req_id to list of waiting TaskCompletionSource objects.
    /// Each auth_req_id can have multiple concurrent waiters (e.g., if client retries).
    /// </summary>
    private readonly ConcurrentDictionary<string, ConcurrentBag<TaskCompletionSource<bool>>> _waiters = new();

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
        var waiters = _waiters.GetOrAdd(authenticationRequestId, _ => new ConcurrentBag<TaskCompletionSource<bool>>());
        waiters.Add(tcs);

        logger.LogDebug(
            "Long-polling request waiting for auth_req_id: {AuthReqId}, timeout: {Timeout}",
            authenticationRequestId,
            timeout);

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
                logger.LogInformation(
                    "Long-polling request received status change notification for auth_req_id: {AuthReqId}",
                    authenticationRequestId);
                return true;
            }

            logger.LogDebug(
                "Long-polling request timed out for auth_req_id: {AuthReqId}",
                authenticationRequestId);
            return false;
        }
        catch (OperationCanceledException)
        {
            logger.LogDebug(
                "Long-polling request cancelled for auth_req_id: {AuthReqId}",
                authenticationRequestId);
            throw;
        }
        finally
        {
            // Cleanup: Remove this waiter (don't need to signal it anymore)
            // Note: If bag is empty after removal, it will be cleaned up on next NotifyStatusChangeAsync
            tcs.TrySetCanceled();
        }
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
            logger.LogDebug(
                "Status changed to {Status} for auth_req_id: {AuthReqId}, but no long-polling requests waiting",
                newStatus,
                authenticationRequestId);
            return Task.CompletedTask;
        }

        logger.LogInformation(
            "Notifying {Count} long-polling request(s) of status change to {Status} for auth_req_id: {AuthReqId}",
            waiters.Count,
            newStatus,
            authenticationRequestId);

        // Signal all waiting tasks
        foreach (var waiter in waiters)
        {
            waiter.TrySetResult(true);
        }

        return Task.CompletedTask;
    }
}
