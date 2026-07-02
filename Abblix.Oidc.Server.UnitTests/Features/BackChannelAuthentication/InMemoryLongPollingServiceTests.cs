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

using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

/// <summary>
/// Pins that <see cref="InMemoryLongPollingService"/> releases its internal waiter state when a
/// long-poll times out. Without cleanup the singleton's waiter map grows without bound for every
/// CIBA request that expires without a notification (CWE-401), which an attacker can drive
/// deliberately. The internal map is inspected by reflection because it has no public surface.
/// </summary>
public class InMemoryLongPollingServiceTests
{
    private static InMemoryLongPollingService CreateService()
        => new(NullLogger<InMemoryLongPollingService>.Instance);

    private static System.Collections.ICollection Waiters(InMemoryLongPollingService service)
    {
        var field = typeof(InMemoryLongPollingService)
            .GetField("_waiters", BindingFlags.Instance | BindingFlags.NonPublic);
        return (System.Collections.ICollection)field!.GetValue(service)!;
    }

    private static int InnerWaiterCount(InMemoryLongPollingService service, string authReqId)
    {
        var field = typeof(InMemoryLongPollingService)
            .GetField("_waiters", BindingFlags.Instance | BindingFlags.NonPublic);
        var outer = (System.Collections.IDictionary)field!.GetValue(service)!;
        return ((System.Collections.ICollection)outer[authReqId]!).Count;
    }

    /// <summary>
    /// A long-poll that times out without a notification must leave no residual entry in the
    /// waiter map. Before the fix the auth_req_id key and its dead TaskCompletionSource live
    /// forever, so the map count stays at 1.
    /// </summary>
    [Fact]
    public async Task WaitForStatusChange_Timeout_RemovesWaiterAndDropsEmptyKey()
    {
        var service = CreateService();

        var completed = await service.WaitForStatusChangeAsync(
            "auth_req_abandoned",
            TimeSpan.FromMilliseconds(50));

        Assert.False(completed);
        Assert.Empty(Waiters(service));
    }

    /// <summary>
    /// A timed-out waiter must remove only its own registration, leaving other live waiters on the
    /// same auth_req_id intact. Before the fix the ConcurrentBag cannot remove a single item, so
    /// the inner collection keeps both entries (count 2) and, after the live waiter ends, the key
    /// still lingers.
    /// </summary>
    [Fact]
    public async Task WaitForStatusChange_Timeout_RemovesOnlyOwnWaiter()
    {
        var service = CreateService();
        const string authReqId = "auth_req_shared";
        using var cts = new CancellationTokenSource();

        // Registers synchronously and keeps the key alive with a long timeout.
        var persistentWait = service.WaitForStatusChangeAsync(
            authReqId,
            TimeSpan.FromMinutes(5),
            cts.Token);

        var timedOut = await service.WaitForStatusChangeAsync(
            authReqId,
            TimeSpan.FromMilliseconds(50));
        Assert.False(timedOut);

        Assert.Equal(1, InnerWaiterCount(service, authReqId));

        // Release the persistent waiter (WhenAny returns the cancelled timeout task, so the method
        // returns false rather than throwing) and confirm the key is then dropped.
        cts.Cancel();
        Assert.False(await persistentWait);
        Assert.Empty(Waiters(service));
    }
}
