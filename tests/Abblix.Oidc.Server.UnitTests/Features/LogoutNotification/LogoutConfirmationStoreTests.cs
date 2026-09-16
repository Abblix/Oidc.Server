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

        Assert.Equal(SessionId, await _store.RedeemAsync(confirmation));
    }

    /// <summary>
    /// Redeeming spends it: a confirmation captured from a page cannot be sent a second time, against whatever
    /// session the browser holds by then.
    /// </summary>
    [Fact]
    public async Task RedeemedConfirmation_IsSpent()
    {
        var confirmation = await _store.IssueAsync(SessionId);

        Assert.Equal(SessionId, await _store.RedeemAsync(confirmation));
        Assert.Null(await _store.RedeemAsync(confirmation));
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

        Assert.Null(await _store.RedeemAsync(confirmation));
    }

    /// <summary>
    /// An answer stops counting once its question has gone stale, which is what bounds how long a page left open
    /// can be submitted and how long each unanswered question occupies the store.
    /// </summary>
    [Fact]
    public async Task Confirmation_StopsCountingAfterItsLifetime()
    {
        _options.LogoutConfirmationLifetime = TimeSpan.FromMilliseconds(50);

        var confirmation = await _store.IssueAsync(SessionId);
        await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);

        Assert.Null(await _store.RedeemAsync(confirmation));
    }

    /// <summary>
    /// Two issues answer with two different values, so one page's answer is never another's.
    /// </summary>
    [Fact]
    public async Task EachIssue_AnswersWithItsOwnValue()
    {
        var first = await _store.IssueAsync(SessionId);
        var second = await _store.IssueAsync(SessionId);

        Assert.NotEqual(first, second);
        Assert.Equal(SessionId, await _store.RedeemAsync(first));
        Assert.Equal(SessionId, await _store.RedeemAsync(second));
    }
}
