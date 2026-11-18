// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// A memory cache whose entries expire by the test's clock, so a test moving time forward sees an entry's absolute
/// expiration pass, which <see cref="MemoryCache"/> judges by the real one.
/// </summary>
internal sealed class TimedMemoryCache(TimeProvider clock) : IMemoryCache
{
    private readonly ConcurrentDictionary<object, Entry> _entries = new();

    public ICacheEntry CreateEntry(object key) => new Entry(key, this);

    public bool TryGetValue(object key, out object? value)
    {
        if (_entries.TryGetValue(key, out var entry) &&
            (entry.AbsoluteExpiration is not { } expires || clock.GetUtcNow() < expires))
        {
            value = entry.Value;
            return true;
        }

        value = null;
        return false;
    }

    public void Remove(object key) => _entries.TryRemove(key, out _);

    public void Dispose()
    {
        // Nothing is held beyond the dictionary
    }

    private sealed class Entry(object key, TimedMemoryCache cache) : ICacheEntry
    {
        public object Key { get; } = key;
        public object? Value { get; set; }
        public DateTimeOffset? AbsoluteExpiration { get; set; }
        public TimeSpan? AbsoluteExpirationRelativeToNow { get; set; }
        public TimeSpan? SlidingExpiration { get; set; }
        public IList<IChangeToken> ExpirationTokens { get; } = [];
        public IList<PostEvictionCallbackRegistration> PostEvictionCallbacks { get; } = [];
        public CacheItemPriority Priority { get; set; }
        public long? Size { get; set; }

        public void Dispose()
        {
            AbsoluteExpiration ??= AbsoluteExpirationRelativeToNow is { } relative
                ? cache.Now + relative
                : null;
            cache._entries[Key] = this;
        }
    }

    private DateTimeOffset Now => clock.GetUtcNow();
}
