// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Storages.Proto;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.LogoutNotification;

/// <summary>
/// Unit tests for <see cref="LogoutConfirmationStore"/>, which issues the question a session's end user is asked
/// before a logout and redeems the answer they send back.
/// </summary>
public class LogoutConfirmationStoreTests
{
    private const string SessionId = "session-1";
    private const string AnotherSessionId = "session-2";

    /// <summary>
    /// How far the one timed row stays from the moment it is about to cross, so a delay that overruns on a
    /// loaded machine does not decide the outcome. Its lifetime and its wait are both stated in these, never in
    /// a number of their own, so the distance holds by arithmetic rather than by a comment saying it does.
    /// </summary>
    private static readonly TimeSpan Margin = TimeSpan.FromMilliseconds(300);

    /// <summary>
    /// A lifetime no row waits out, for the half of a row that has to stay answerable while its sibling goes
    /// stale. Deliberately not the shipped default, so that half is a lifetime this row configured rather than
    /// one it inherited.
    /// </summary>
    private static readonly TimeSpan LongerThanTheRow = TimeSpan.FromMinutes(7);

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
    /// The value the end user's page sends back is the answer to that session's question.
    /// </summary>
    [Fact]
    public async Task TheIssuedValue_AnswersItsSession()
    {
        var confirmation = await _store.IssueAsync(SessionId);

        Assert.True(await _store.RedeemLogoutConfirmationAsync(SessionId, confirmation));
    }

    /// <summary>
    /// Answering spends the question: the same value sent again is no longer an answer, so a confirmation captured
    /// from a page cannot be replayed against whatever session the browser holds by then.
    /// </summary>
    [Fact]
    public async Task AnAnsweredQuestion_IsSpent()
    {
        var confirmation = await _store.IssueAsync(SessionId);

        Assert.True(await _store.RedeemLogoutConfirmationAsync(SessionId, confirmation));
        Assert.False(await _store.RedeemLogoutConfirmationAsync(SessionId, confirmation));
    }

    /// <summary>
    /// An answer belongs to the session it was issued for. Without this, a value obtained in one browser would end
    /// the session of whoever else this server is serving.
    /// </summary>
    [Fact]
    public async Task AnAnswerFromAnotherSession_IsNotAnAnswer()
    {
        var mine = await _store.IssueAsync(SessionId);
        await _store.IssueAsync(AnotherSessionId);

        Assert.False(await _store.RedeemLogoutConfirmationAsync(AnotherSessionId, mine));
        Assert.True(await _store.RedeemLogoutConfirmationAsync(SessionId, mine));
    }

    /// <summary>
    /// A value this server never issued is no answer, which is the whole difference between an answer and a caller
    /// asserting that the end user agreed. A wrong value also leaves the real question standing, so somebody
    /// sending one cannot stop the end user from answering.
    /// </summary>
    [Theory]
    [InlineData("a-value-nobody-issued")]
    [InlineData("")]
    [InlineData(" ")]
    public async Task AValueNobodyIssued_IsNotAnAnswer(string confirmation)
    {
        var outstanding = await _store.IssueAsync(SessionId);

        Assert.False(await _store.RedeemLogoutConfirmationAsync(SessionId, confirmation));
        Assert.True(await _store.RedeemLogoutConfirmationAsync(SessionId, outstanding));
    }

    /// <summary>
    /// A request that carries the parameter and nothing in it answers nothing, whatever the store holds: two
    /// empty values compare equal, so a record that somehow held none would otherwise be answerable by anybody.
    /// </summary>
    [Fact]
    public async Task AnEmptyValue_AnswersNothing()
    {
        var storage = new HoldingOneRecord(new LogoutConfirmation { Confirmation = string.Empty });
        var store = new LogoutConfirmationStore(storage, new EntityStorageKeyFactory(), Options.Create(_options));

        Assert.False(await store.RedeemLogoutConfirmationAsync(SessionId, string.Empty));
    }

    /// <summary>
    /// A session with no question outstanding has nothing to answer, which is what a request carrying a value
    /// nobody asked for looks like.
    /// </summary>
    [Fact]
    public async Task ASessionNobodyAsked_HasNoAnswer()
    {
        var confirmation = await _store.IssueAsync(SessionId);

        Assert.False(await _store.RedeemLogoutConfirmationAsync(AnotherSessionId, confirmation));
    }

    /// <summary>
    /// Asking again is the same question. Anyone can make a browser reach the logout address, so issuing a fresh
    /// value here would let a request arriving while the end user reads the page void the answer they are about
    /// to give. The store's size is not what this buys: the key is the session's either way.
    /// </summary>
    [Fact]
    public async Task AskingAgain_IsTheSameQuestion()
    {
        var first = await _store.IssueAsync(SessionId);
        var second = await _store.IssueAsync(SessionId);

        Assert.Equal(first, second);
        Assert.True(await _store.RedeemLogoutConfirmationAsync(SessionId, first));
    }

    /// <summary>
    /// And once it has been answered the next request asks afresh, so the value just given stops being one.
    /// </summary>
    [Fact]
    public async Task AskingAfterAnAnswer_IssuesAfresh()
    {
        var answered = await _store.IssueAsync(SessionId);
        Assert.True(await _store.RedeemLogoutConfirmationAsync(SessionId, answered));

        var next = await _store.IssueAsync(SessionId);

        Assert.NotEqual(answered, next);
        Assert.False(await _store.RedeemLogoutConfirmationAsync(SessionId, answered));
        Assert.True(await _store.RedeemLogoutConfirmationAsync(SessionId, next));
    }

    /// <summary>
    /// Asking again hands the question back without giving it a longer life, so repeated asking cannot keep one
    /// question alive indefinitely.
    /// </summary>
    [Fact]
    public async Task AskingAgain_DoesNotExtendTheQuestion()
    {
        // A question's life is carried by the write that created it, so extending it means writing again. This
        // says so directly rather than through the clock: a storage that refuses writes answers the standing
        // record, and a hand-back that wrote would fault instead of handing it back. Waiting for an expiry would
        // test the same property by arithmetic on a machine whose delays overrun.
        var storage = new HoldingOneRecord(new LogoutConfirmation { Confirmation = "the-standing-question" });
        var store = new LogoutConfirmationStore(storage, new EntityStorageKeyFactory(), Options.Create(_options));

        Assert.Equal("the-standing-question", await store.IssueAsync(SessionId));
    }

    /// <summary>
    /// An answer stops counting once its question has gone stale, which bounds how long a page left open can be
    /// submitted and how long an unanswered question occupies the store.
    /// </summary>
    [Fact]
    public async Task AQuestion_StopsCountingAfterItsLifetime()
    {
        _options.LogoutConfirmationLifetime = LongerThanTheRow;
        var stillGood = await _store.IssueAsync(SessionId);

        // The same store, so the only difference between the two halves is how long the question was good for.
        _options.LogoutConfirmationLifetime = Margin;
        var goneStale = await _store.IssueAsync(AnotherSessionId);

        // One margin past the end of the short question and nowhere near the end of the long one.
        await Task.Delay(Margin + Margin, TestContext.Current.CancellationToken);

        // The control: the delay alone does not make an answer stop counting, so the refusal below is the
        // lifetime and not the wait.
        Assert.True(await _store.RedeemLogoutConfirmationAsync(SessionId, stillGood));
        Assert.False(await _store.RedeemLogoutConfirmationAsync(AnotherSessionId, goneStale));
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
    /// A storage answering every read with one record, so a record this library would never write itself can be
    /// put in front of the store, and refusing to create or replace one, so a row can say that a path does not
    /// write by running it rather than by asserting about it. The store does create a record, on the path where
    /// a read answers nothing, which this storage never takes. Removal stays open because answering a question
    /// removes it, and a row about that path would otherwise be unable to run at all.
    /// </summary>
    private sealed class HoldingOneRecord(LogoutConfirmation held) : IEntityStorage
    {
        public Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
            => Task.FromResult((T?)(object)held);

        public Task RemoveAsync(string key, CancellationToken? token = null) => Task.CompletedTask;

        public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
            => throw new NotSupportedException();

        public Task<bool> TrySetIfAbsentAsync<T>(
            string key, T value, StorageOptions options, CancellationToken? token = null)
            => throw new NotSupportedException();
    }
}
