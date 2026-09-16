// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.LogoutNotification;

/// <summary>
/// Unit tests for <see cref="LogoutConfirmationStore"/>, which issues and redeems the value carrying an end user's
/// answer to the logout question back to this server.
/// </summary>
public class LogoutConfirmationStoreTests
{
    private const string SessionId = "session-1";

    private readonly OidcOptions _options = new();
    private readonly LogoutConfirmationStore _store;

    public LogoutConfirmationStoreTests()
    {
        // The in-box storage over an in-memory cache, which is the production path for a single-node deployment.
        var storage = new DistributedCacheStorage(
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            new JsonBinarySerializer());

        _store = new LogoutConfirmationStore(storage, new EntityStorageKeyFactory(), Options.Create(_options));
    }

    /// <summary>
    /// The issued value answers for the session it was issued for, which is what lets the request end that session
    /// and no other.
    /// </summary>
    [Fact]
    public async Task IssuedConfirmation_NamesItsSession()
    {
        var confirmation = await _store.IssueAsync(SessionId);

        Assert.Equal(SessionId, await _store.RedeemLogoutConfirmationAsync(confirmation));
    }

    /// <summary>
    /// Redeeming spends it: a confirmation captured from a page cannot be sent a second time, against whatever
    /// session the browser holds by then.
    /// </summary>
    [Fact]
    public async Task RedeemedConfirmation_IsSpent()
    {
        var confirmation = await _store.IssueAsync(SessionId);

        Assert.Equal(SessionId, await _store.RedeemLogoutConfirmationAsync(confirmation));
        Assert.Null(await _store.RedeemLogoutConfirmationAsync(confirmation));
    }

    /// <summary>
    /// A value this server never issued names nothing, which is the whole difference between an answer and a
    /// caller asserting that the end user agreed.
    /// </summary>
    [Theory]
    [InlineData("a-value-nobody-issued")]
    [InlineData("")]
    [InlineData(" ")]
    public async Task ValueNobodyIssued_NamesNothing(string confirmation)
    {
        await _store.IssueAsync(SessionId);

        Assert.Null(await _store.RedeemLogoutConfirmationAsync(confirmation));
    }

    /// <summary>
    /// An answer stops counting once its question has gone stale, which is what bounds how long a page left open
    /// can be submitted and how long each unanswered question occupies the store.
    /// </summary>
    [Fact]
    public async Task Confirmation_StopsCountingAfterItsLifetime()
    {
        _options.LogoutConfirmationLifetime = TimeSpan.FromMinutes(10);
        var stillGood = await _store.IssueAsync(SessionId);

        // The same store, so the only difference between the two halves is how long the question was good for.
        _options.LogoutConfirmationLifetime = TimeSpan.FromMilliseconds(50);
        var goneStale = await _store.IssueAsync("session-2");

        await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);

        // The control: the delay alone does not make an answer stop counting, so the refusal below is the
        // lifetime and not the wait.
        Assert.Equal(SessionId, await _store.RedeemLogoutConfirmationAsync(stillGood));
        Assert.Null(await _store.RedeemLogoutConfirmationAsync(goneStale));
    }

    /// <summary>
    /// A lifetime that keeps nothing is refused by the storage itself, which is why the settings are checked at
    /// startup: without that check a deployment boots and every logout question faults here instead.
    /// </summary>
    [Fact]
    public async Task ALifetimeOfZero_IsRefusedByTheStorage()
    {
        _options.LogoutConfirmationLifetime = TimeSpan.Zero;

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _store.IssueAsync(SessionId));
    }

    /// <summary>
    /// Asking the same session again hands back the question already outstanding. Anyone can make a browser reach
    /// the logout address, so a value per request would let an outsider fill the store with questions nobody will
    /// answer.
    /// </summary>
    [Fact]
    public async Task AskingAgain_ReUsesTheOutstandingQuestion()
    {
        var first = await _store.IssueAsync(SessionId);
        var second = await _store.IssueAsync(SessionId);

        Assert.Equal(first, second);
    }

    /// <summary>
    /// Two sessions are two questions, or one browser's answer would end the other's session.
    /// </summary>
    [Fact]
    public async Task EachSession_GetsItsOwnValue()
    {
        var mine = await _store.IssueAsync(SessionId);
        var theirs = await _store.IssueAsync("session-2");

        Assert.NotEqual(mine, theirs);
        Assert.Equal(SessionId, await _store.RedeemLogoutConfirmationAsync(mine));
        Assert.Equal("session-2", await _store.RedeemLogoutConfirmationAsync(theirs));
    }

    /// <summary>
    /// Once answered, the next question is a fresh one: handing back the value just spent would have every logout
    /// after the first refused.
    /// </summary>
    [Fact]
    public async Task AskingAfterAnAnswer_IssuesAfresh()
    {
        var answered = await _store.IssueAsync(SessionId);
        Assert.Equal(SessionId, await _store.RedeemLogoutConfirmationAsync(answered));

        var next = await _store.IssueAsync(SessionId);

        Assert.NotEqual(answered, next);
        Assert.Equal(SessionId, await _store.RedeemLogoutConfirmationAsync(next));
    }
}
