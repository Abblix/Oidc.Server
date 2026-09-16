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
/// Unit tests for <see cref="LogoutConfirmationStore"/>, which issues the question a session's end user is asked
/// before a logout and redeems the answer they send back.
/// </summary>
public class LogoutConfirmationStoreTests
{
    private const string SessionId = "session-1";
    private const string AnotherSessionId = "session-2";

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
    /// Asking again is the same question. Anyone can make a browser reach the logout address, so a question per
    /// request would both fill the store and let a request arriving while the end user reads the page void the
    /// answer they are about to give.
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
    /// An answer stops counting once its question has gone stale, which bounds how long a page left open can be
    /// submitted and how long an unanswered question occupies the store.
    /// </summary>
    [Fact]
    public async Task AQuestion_StopsCountingAfterItsLifetime()
    {
        _options.LogoutConfirmationLifetime = TimeSpan.FromMinutes(10);
        var stillGood = await _store.IssueAsync(SessionId);

        // The same store, so the only difference between the two halves is how long the question was good for.
        _options.LogoutConfirmationLifetime = TimeSpan.FromMilliseconds(50);
        var goneStale = await _store.IssueAsync(AnotherSessionId);

        await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);

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
}
