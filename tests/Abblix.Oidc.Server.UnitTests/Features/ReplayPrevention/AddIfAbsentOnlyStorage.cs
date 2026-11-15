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
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.UnitTests.Features.ReplayPrevention;

/// <summary>
/// A storage like a store every node shares, whose add-if-absent is its one atomic operation: it decides there, and
/// every read or plain write is refused, so a replay cache that read first or wrote unconditionally fails loudly
/// instead of passing by luck.
/// </summary>
internal sealed class AddIfAbsentOnlyStorage : IEntityStorage
{
    private readonly ConcurrentDictionary<string, object?> _entries = new();
    private readonly ConcurrentQueue<string> _claimed = new();
    private readonly ConcurrentQueue<StorageOptions> _lifetimes = new();

    /// <summary>The key of every add-if-absent call, in the order they came.</summary>
    public IReadOnlyCollection<string> Claimed => _claimed.ToArray();

    /// <summary>The expiration policy of every add-if-absent call, in the order they came.</summary>
    public IReadOnlyCollection<StorageOptions> Lifetimes => _lifetimes.ToArray();

    /// <summary>The keys held now.</summary>
    public IReadOnlyCollection<string> Held => [.. _entries.Keys];

    public Task<bool> TrySetIfAbsentAsync<T>(
        string key, T value, StorageOptions options, CancellationToken? token = null)
    {
        _claimed.Enqueue(key);
        _lifetimes.Enqueue(options);
        return Task.FromResult(_entries.TryAdd(key, value));
    }

    public Task RemoveAsync(string key, CancellationToken? token = null)
    {
        _entries.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
        => throw new NotSupportedException(nameof(SetAsync));

    public Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
        => throw new NotSupportedException(nameof(GetAsync));

    public Task<bool> TryReplaceAsync<T>(
        string key, T expected, T value, StorageOptions options, CancellationToken? token = null)
        => throw new NotSupportedException(nameof(TryReplaceAsync));

    public Task<bool> TryExtendAsync(string key, StorageOptions options, CancellationToken? token = null)
        => throw new NotSupportedException(nameof(TryExtendAsync));
}
