// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Abblix.Tests.Shared;

/// <summary>
/// A host's own distributed cache that records the keys written to it, so a test can tell whether the library stored
/// in the host's cache rather than in one of its own.
/// </summary>
internal sealed class RecordingDistributedCache : IDistributedCache
{
    private readonly MemoryDistributedCache _inner = new(Options.Create(new MemoryDistributedCacheOptions()));
    private readonly List<string> _written = [];

    public IReadOnlyList<string> Written
    {
        get
        {
            lock (_written) return [.. _written];
        }
    }

    public byte[]? Get(string key) => _inner.Get(key);

    public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => _inner.GetAsync(key, token);

    public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
    {
        Record(key);
        _inner.Set(key, value, options);
    }

    public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
    {
        Record(key);
        return _inner.SetAsync(key, value, options, token);
    }

    public void Refresh(string key) => _inner.Refresh(key);

    public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);

    public void Remove(string key) => _inner.Remove(key);

    public Task RemoveAsync(string key, CancellationToken token = default) => _inner.RemoveAsync(key, token);

    private void Record(string key)
    {
        lock (_written) _written.Add(key);
    }
}
