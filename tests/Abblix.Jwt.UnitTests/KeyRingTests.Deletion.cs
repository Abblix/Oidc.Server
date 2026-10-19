// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Jwt.UnitTests;

// Removing the entries of partitions from the store, and the one store every part of the ring shares
public sealed partial class KeyRingTests
{
    /// <summary>
    /// Deleting a partition removes its entries from the store and leaves another partition's entries in place.
    /// </summary>
    [Fact]
    public async Task DeletingAPartition_RemovesItsEntriesAlone()
    {
        var (rings, _, store) = CreateRings(TimeSpan.FromHours(1), new FakeTimeProvider(Now), null, "acme", "globex");
        foreach (var (_, ring, source) in rings.BeginRound())
            await ring.RefreshAsync(source, TestContext.Current.CancellationToken);

        var failures = await rings.DeleteAsync(["acme"], TestContext.Current.CancellationToken);

        Assert.Empty(failures);
        Assert.DoesNotContain(store.Entries, entry => entry.Id.StartsWith("acme.", StringComparison.Ordinal));
        Assert.Contains(store.Entries, entry => entry.Id.StartsWith("globex.", StringComparison.Ordinal));
    }

    /// <summary>
    /// A host's store registered for each resolution still gives the ring one store: the keys the refresh mints are
    /// the ones a deletion removes.
    /// </summary>
    [Fact]
    public async Task AStoreRegisteredPerResolution_IsOneStoreForTheWholeRing()
    {
        var stores = new List<FakeStore>();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton(StubCustodian(_keyEncryptionKey));
        services.AddTransient<IKeyRingStore>(_ =>
        {
            var store = new FakeStore();
            stores.Add(store);
            return store;
        });
        services.ComposeExternalKeyBackends();
        services.AddKeyRing(new MintedKeys { KeyEncryptionKeyName = KeyEncryptionKeyName });
        await using var provider = services.BuildServiceProvider();
        var ct = TestContext.Current.CancellationToken;

        var rings = provider.GetRequiredService<IKeyRings>();
        var refresh = provider.GetServices<IHostedService>().OfType<KeyRingRefreshService>().Single();
        await refresh.StartAsync(ct);
        Assert.NotEmpty(stores.SelectMany(store => store.Entries));

        Assert.Empty(await rings.DeleteAsync([KeyRingOptions.DefaultPartition], ct));
        await refresh.StopAsync(ct);

        Assert.Empty(stores.SelectMany(store => store.Entries));
    }

    /// <summary>
    /// A deletion stopped before it starts removes nothing and reports every partition it was asked for as
    /// canceled.
    /// </summary>
    [Fact]
    public async Task ACanceledDeletion_KeepsTheEntries_AndReportsEveryPartition()
    {
        var (rings, _, store) = CreateRings(TimeSpan.FromHours(1), new FakeTimeProvider(Now), null, "acme", "globex");
        foreach (var (_, ring, source) in rings.BeginRound())
            await ring.RefreshAsync(source, TestContext.Current.CancellationToken);
        var stored = store.Entries.Count;

        var failures = await rings.DeleteAsync(["acme", "globex"], new CancellationToken(canceled: true));

        Assert.Equal(["acme", "globex"], failures.Keys.Order(StringComparer.Ordinal));
        Assert.All(failures.Values, failure => Assert.IsType<OperationCanceledException>(failure));
        Assert.Equal(stored, store.Entries.Count);
    }
}
