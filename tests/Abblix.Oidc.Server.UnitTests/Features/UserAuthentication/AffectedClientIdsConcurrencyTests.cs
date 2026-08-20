// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.UserAuthentication;

/// <summary>
/// What <see cref="AuthSession.AffectedClientIds"/> must survive when a host hands the same session instance to
/// several requests at once: additions from different threads, and an enumeration running while another thread
/// adds.
/// </summary>
/// <remarks>
/// A host that caches the session and serves one instance to concurrent requests is the case these guard. The
/// list is written by the authorization endpoint, which records every client that took part in the session, and
/// read by the end-session endpoint, which notifies exactly those clients that the user signed out. So a lost
/// addition is a client that never learns the user left - its local session outlives the logout - and a torn
/// enumeration is a 500 on the way out.
///
/// Note the boundary this does NOT cross: the cookie-backed <c>AuthenticationSchemeAdapter</c> rebuilds a fresh
/// session from claims on every request, so concurrent requests there never share an instance and these
/// guarantees do not reach them. Their lost updates are a property of read-modify-write against the browser's
/// cookie and can only be closed by a store that adds atomically.
/// </remarks>
public class AffectedClientIdsConcurrencyTests
{
    private const int Writers = 16;
    private const int PerWriter = 64;

    private static AuthSession NewSession() => new(
        Subject: "subject",
        SessionId: "session",
        AuthenticationTime: TimeProvider.System.GetUtcNow(),
        IdentityProvider: "test");

    /// <summary>
    /// Every client added concurrently is present afterwards. A plain list loses additions here, and it loses
    /// them silently: the writer sees no error, and the client simply never appears in the logout notice.
    /// </summary>
    [Fact]
    public async Task Concurrent_additions_all_survive()
    {
        var session = NewSession();
        var expected = Enumerable
            .Range(0, Writers * PerWriter)
            .Select(i => $"client-{i}")
            .ToArray();

        await Parallel.ForEachAsync(
            Enumerable.Range(0, Writers),
            TestContext.Current.CancellationToken,
            (writer, _) =>
            {
                for (var i = 0; i < PerWriter; i++)
                    session.AffectedClientIds.Add(expected[writer * PerWriter + i]);

                return ValueTask.CompletedTask;
            });

        Assert.Equal(expected.Length, session.AffectedClientIds.Count);
        Assert.Empty(expected.Except(session.AffectedClientIds));
    }

    /// <summary>
    /// The same client id arriving from several threads at once is stored once. A duplicate is not cosmetic:
    /// the end-session endpoint notifies per entry, so a client would be asked to log out twice.
    /// </summary>
    [Fact]
    public async Task The_same_client_added_concurrently_is_stored_once()
    {
        var session = NewSession();

        await Parallel.ForEachAsync(
            Enumerable.Range(0, Writers),
            TestContext.Current.CancellationToken,
            (_, _) =>
            {
                for (var i = 0; i < PerWriter; i++)
                    session.AffectedClientIds.Add("the-same-client");

                return ValueTask.CompletedTask;
            });

        Assert.Equal(["the-same-client"], session.AffectedClientIds);
    }

    /// <summary>
    /// Enumerating while another thread adds must neither throw nor tear. This is the shape the end-session
    /// endpoint runs in - it iterates the ids and awaits a client lookup inside the loop, so the enumeration is
    /// open across suspension points and any concurrent write lands in the middle of it.
    /// </summary>
    [Fact]
    public async Task Enumerating_while_another_thread_adds_neither_throws_nor_tears()
    {
        var session = NewSession();
        session.AffectedClientIds.Add("already-there");

        using var stop = new CancellationTokenSource();

        var writer = Task.Run(() =>
        {
            for (var i = 0; !stop.IsCancellationRequested && i < Writers * PerWriter; i++)
                session.AffectedClientIds.Add($"late-{i}");
        }, TestContext.Current.CancellationToken);

        try
        {
            for (var round = 0; round < 200; round++)
            {
                var seen = new List<string>();
                foreach (var clientId in session.AffectedClientIds)
                    seen.Add(clientId);

                // Whatever else the snapshot caught, what was there before the writer started must still be in
                // it: a reader that can lose an existing entry is worse than one that misses a new one.
                Assert.Contains("already-there", seen);
            }
        }
        finally
        {
            await stop.CancelAsync();
            await writer;
        }
    }
}
