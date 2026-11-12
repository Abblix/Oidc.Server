// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Time.Testing;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// Pins what the dictionary promises: an entry is seen until its lifetime ends and never after, an expired entry
/// gives way to a new one, a renewal restarts only the value it names, and expired entries do not pile up.
/// </summary>
public class ExpiringDictionaryTests
{
    private const string Key = "https://issuer.example.com/jwks";

    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(30);

    [Fact]
    public void AValue_IsSeenUntilItsLifetimeEnds_AndNotAfter()
    {
        var time = new FakeTimeProvider();
        var dictionary = new ExpiringDictionary<string, string>(time);

        Assert.True(dictionary.TryAdd(Key, "key-set", Lifetime));
        time.Advance(Lifetime - TimeSpan.FromSeconds(1));
        Assert.True(dictionary.TryGetValue(Key, out var value));
        Assert.Equal("key-set", value);

        time.Advance(TimeSpan.FromSeconds(1));
        Assert.False(dictionary.TryGetValue(Key, out _));
    }

    /// <summary>
    /// A live entry keeps its key, and an expired one gives it up to the next addition.
    /// </summary>
    [Fact]
    public void Adding_IsRefusedOverALiveEntry_AndReplacesAnExpiredOne()
    {
        var time = new FakeTimeProvider();
        var dictionary = new ExpiringDictionary<string, string>(time);
        dictionary.TryAdd(Key, "first", Lifetime);

        Assert.False(dictionary.TryAdd(Key, "second", Lifetime));
        time.Advance(Lifetime);
        Assert.True(dictionary.TryAdd(Key, "third", Lifetime));

        Assert.True(dictionary.TryGetValue(Key, out var value));
        Assert.Equal("third", value);
    }

    /// <summary>
    /// A renewal starts the lifetime again from now, and only for the value the caller holds: a key that has moved on
    /// to another value is left alone.
    /// </summary>
    [Fact]
    public void Renewing_RestartsTheLifetime_OnlyOfTheValueNamed()
    {
        var time = new FakeTimeProvider();
        var dictionary = new ExpiringDictionary<string, string>(time);
        dictionary.TryAdd(Key, "key-set", Lifetime);

        time.Advance(Lifetime - TimeSpan.FromSeconds(1));
        Assert.False(dictionary.TryRenew(Key, "another", Lifetime));
        Assert.True(dictionary.TryRenew(Key, "key-set", Lifetime));

        time.Advance(Lifetime - TimeSpan.FromSeconds(1));
        Assert.True(dictionary.TryGetValue(Key, out _));
    }

    /// <summary>
    /// An entry that has expired stays expired: renewing it fails and it is still not found, whether or not a sweep
    /// has removed it yet, so a sliding expiry never brings back what has already lapsed.
    /// </summary>
    [Fact]
    public void Renewing_AnExpiredEntry_DoesNotBringItBack()
    {
        var time = new FakeTimeProvider();
        var dictionary = new ExpiringDictionary<string, string>(time);
        dictionary.TryAdd(Key, "key-set", Lifetime);

        time.Advance(Lifetime);

        Assert.False(dictionary.TryRenew(Key, "key-set", Lifetime));
        Assert.False(dictionary.TryGetValue(Key, out _));
    }

    /// <summary>
    /// A renewal compares the value it names with the one held by the comparer the dictionary was given, and by the
    /// default equality when it was given none.
    /// </summary>
    [Fact]
    public void Renewing_ComparesValuesByTheComparerGiven()
    {
        var time = new FakeTimeProvider();
        var ignoringCase = new ExpiringDictionary<string, string>(time, valueComparer: StringComparer.OrdinalIgnoreCase);
        var byDefault = new ExpiringDictionary<string, string>(time);
        ignoringCase.TryAdd(Key, "key-set", Lifetime);
        byDefault.TryAdd(Key, "key-set", Lifetime);

        Assert.True(ignoringCase.TryRenew(Key, "KEY-SET", Lifetime));
        Assert.False(byDefault.TryRenew(Key, "KEY-SET", Lifetime));
    }

    [Fact]
    public void AnInfiniteLifetime_NeverExpires()
    {
        var time = new FakeTimeProvider();
        var dictionary = new ExpiringDictionary<string, string>(time);
        dictionary.TryAdd(Key, "key-set", Timeout.InfiniteTimeSpan);

        time.Advance(TimeSpan.FromDays(3650));

        Assert.True(dictionary.TryGetValue(Key, out _));
    }

    /// <summary>
    /// A lifetime longer than any timer allows is counted rather than refused.
    /// </summary>
    [Fact]
    public void TheLongestLifetime_IsCounted()
    {
        var dictionary = new ExpiringDictionary<string, string>(TimeProvider.System);

        Assert.True(dictionary.TryAdd(Key, "key-set", TimeSpan.MaxValue));

        Assert.True(dictionary.TryGetValue(Key, out _));
    }

    [Fact]
    public void AZeroLifetime_HasExpiredAlready()
    {
        var dictionary = new ExpiringDictionary<string, string>(new FakeTimeProvider());

        Assert.True(dictionary.TryAdd(Key, "key-set", TimeSpan.Zero));

        Assert.False(dictionary.TryGetValue(Key, out _));
        Assert.True(dictionary.TryAdd(Key, "next", Lifetime));
    }

    /// <summary>
    /// A stream of keys nobody uses twice does not pile up: once their lifetime has passed, the entries are swept as
    /// later keys arrive, so the dictionary holds about the keys still alive rather than every key ever seen.
    /// </summary>
    [Fact]
    public void ExpiredEntries_AreSweptAsNewKeysArrive()
    {
        const int keysPerWave = 1000;
        var time = new FakeTimeProvider();
        var dictionary = new ExpiringDictionary<string, string>(time);

        for (var index = 0; index < keysPerWave; index++)
            dictionary.TryAdd($"first-{index}", "key-set", Lifetime);
        time.Advance(Lifetime);
        for (var index = 0; index < keysPerWave; index++)
            dictionary.TryAdd($"second-{index}", "key-set", Lifetime);

        Assert.InRange(dictionary.Count, keysPerWave, keysPerWave + keysPerWave / 2);
    }
}
