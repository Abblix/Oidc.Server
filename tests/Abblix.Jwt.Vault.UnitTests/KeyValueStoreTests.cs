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

using System.Net;
using System.Text.Json;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// Exercises the KV v2 wire contract of <see cref="KeyValueStore"/> against a stub transport: the cas=0 write
/// that decides which pod mints a period, the losing side of that race, and the empty-ring and deleted-entry cases
/// a running deployment meets.
/// </summary>
public sealed class KeyValueStoreTests : IDisposable
{
    private readonly List<HttpClient> _httpClients = [];

    private static readonly StoredKey Entry = new()
    {
        Id = "sig-RS256-20260717T000000Z",
        Jwe = "header.wrappedkey.iv.ciphertext.tag",
        CreatedAt = new DateTimeOffset(2026, 7, 17, 0, 0, 0, TimeSpan.Zero),
    };

    private KeyValueStore StoreOver(StubHttpMessageHandler handler)
    {
        // The base address stops at /v1/, not at a mount: KV lives on a different mount than Transit, so the
        // store spells its mount into every path.
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.test/v1/") };
        _httpClients.Add(httpClient);

        return new KeyValueStore(
            NullLogger<KeyValueStore>.Instance,
            new StubHttpClientFactory(httpClient),
            Options.Create(new VaultKeyValueOptions { Mount = "secret", Path = "oidc-keyring" }));
    }

    public void Dispose()
    {
        foreach (var httpClient in _httpClients)
            httpClient.Dispose();
    }

    [Fact]
    public async Task TryAddAsync_WritesWithCasZero_SoOnlyTheFirstPodCanWin()
    {
        HttpRequestMessage? seen = null;
        string body = "";
        var handler = new StubHttpMessageHandler((request, payload) =>
        {
            (seen, body) = (request, payload);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new { data = new { version = 1 } });
        });

        var won = await StoreOver(handler).TryAddAsync(Entry, TestContext.Current.CancellationToken);

        Assert.True(won);
        Assert.Equal("https://vault.test/v1/secret/data/oidc-keyring/sig-RS256-20260717T000000Z", seen!.RequestUri!.ToString());

        // cas=0 is the whole coordination: it means "create only if this path never existed", so two pods minting
        // the same period cannot both succeed.
        using var sent = JsonDocument.Parse(body);
        Assert.Equal(0, sent.RootElement.GetProperty("options").GetProperty("cas").GetInt32());
        Assert.Equal(Entry.Jwe, sent.RootElement.GetProperty("data").GetProperty("jwe").GetString());
    }

    [Fact]
    public async Task TryAddAsync_ReportsLost_WhenAnotherPodTookThePeriod()
    {
        // The winner wrote version 1, so our cas=0 write loses with this 400. Reading the entry back finds the
        // winner's key, which is how a genuine race is told from a wedge: losing is routine, its key is as good
        // as ours, and the caller drops what it generated.
        var handler = new StubHttpMessageHandler((request, _) => request.Method.Method switch
        {
            "POST" => StubHttpMessageHandler.Json(
                HttpStatusCode.BadRequest,
                new { errors = new[] { "check-and-set parameter did not match the current version" } }),

            _ => StubHttpMessageHandler.Json(
                HttpStatusCode.OK,
                new { data = new { data = new { jwe = Entry.Jwe, createdAt = Entry.CreatedAt.ToString("O") } } }),
        });

        var won = await StoreOver(handler).TryAddAsync(Entry, TestContext.Current.CancellationToken);

        Assert.False(won);
    }

    [Fact]
    public async Task TryAddAsync_Throws_WhenASoftDeletedVersionWedgesThePeriod()
    {
        // An operator's `vault kv delete` leaves the metadata, so cas=0 keeps failing, but the data reads 404.
        // No pod can win this period: fail loud so it is diagnosed, not wedged forever as "another pod won".
        var handler = new StubHttpMessageHandler((request, _) => request.Method.Method switch
        {
            "POST" => StubHttpMessageHandler.Json(
                HttpStatusCode.BadRequest,
                new { errors = new[] { "check-and-set parameter did not match the current version" } }),

            _ => StubHttpMessageHandler.Json(HttpStatusCode.NotFound, new { errors = Array.Empty<string>() }),
        });

        var store = StoreOver(handler);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.TryAddAsync(Entry, TestContext.Current.CancellationToken));

        Assert.Contains("soft-deleted", error.Message);
    }

    [Fact]
    public async Task TryAddAsync_Throws_WhenTheRequestIsRejectedForAnotherReason()
    {
        // A 400 is also how Vault reports a malformed request, and that is a bug, not a lost race. Telling them
        // apart by message is what keeps a real failure from being read as "another pod won".
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.BadRequest, new { errors = new[] { "missing client token" } }));

        var store = StoreOver(handler);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.TryAddAsync(Entry, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LoadAsync_ReturnsEmpty_WhenNobodyHasMintedYet()
    {
        // The first pod ever to run finds no ring at all. That is the normal bootstrap, not a failure: it is
        // supposed to find it empty and mint into it.
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.NotFound, new { errors = Array.Empty<string>() }));

        var entries = await StoreOver(handler).LoadAsync(TestContext.Current.CancellationToken);

        Assert.Empty(entries);
    }

    [Fact]
    public async Task LoadAsync_ListsThenReadsEachEntry()
    {
        var handler = new StubHttpMessageHandler((request, _) => request.Method.Method switch
        {
            "LIST" => StubHttpMessageHandler.Json(
                HttpStatusCode.OK, new { data = new { keys = new[] { Entry.Id } } }),

            _ => StubHttpMessageHandler.Json(
                HttpStatusCode.OK,
                new { data = new { data = new { jwe = Entry.Jwe, createdAt = Entry.CreatedAt.ToString("O") } } }),
        });

        var entries = await StoreOver(handler).LoadAsync(TestContext.Current.CancellationToken);

        var entry = Assert.Single(entries);
        Assert.Equal(Entry.Id, entry.Id);
        Assert.Equal(Entry.Jwe, entry.Jwe);
        Assert.Equal(Entry.CreatedAt, entry.CreatedAt);
    }

    [Fact]
    public async Task RemoveAsync_TreatsAnAbsentEntryAsDone()
    {
        // Two pods may retire the same expired key. Removing what is already gone is the outcome asked for.
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.NotFound, new { errors = Array.Empty<string>() }));

        var error = await Record.ExceptionAsync(
            () => StoreOver(handler).RemoveAsync(Entry.Id, TestContext.Current.CancellationToken));

        Assert.Null(error);
    }
}
