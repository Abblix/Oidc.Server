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
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// A storage that, once, runs somebody else's whole cycle in the middle of one caller's operation on a
/// named key.
/// </summary>
/// <remarks>
/// Two callers meeting at one key is a race with many orderings and only one of them loses anything, so a
/// test that fires threads and hopes reproduces the loss sometimes - which is the same as passing for the
/// wrong reason. This produces the ordering that matters, once, deterministically.
/// <para>
/// Which ordering that is depends on what the code under test does with the key. Where it reads a record,
/// changes it and writes it back, the damaging ordering puts the other caller's whole cycle inside the
/// READ: the second writer finishes before the first one writes, and its change is overwritten.
/// Where each event instead claims a key of its own, the ordering to drive is inside the CLAIM: the other
/// caller arrives once this one has taken its key and must therefore be given another.
/// </para>
/// <para>
/// Shared rather than nested in one suite, because every flow that meets another caller at one key needs
/// the same orderings, and a second copy is a second set of semantics to keep in step.
/// </para>
/// <para>
/// Each hook is armed once and disarmed on use, so the other caller's own operations on the same key do
/// not recurse.
/// </para>
/// </remarks>
/// <param name="inner">The storage every call is forwarded to.</param>
/// <param name="watched">The key whose operations let the other caller in.</param>
public sealed class LetsAnotherCallerIn(IEntityStorage inner, string watched) : IEntityStorage
{
    private Func<Task>? _onRead;
    private Func<Task>? _onClaim;

    /// <summary>
    /// Arms the interleaving for a read-modify-write: the next read of the watched key runs this, once,
    /// before answering.
    /// </summary>
    public void OnNextReadOf(Func<Task> other) => _onRead = other;

    /// <summary>
    /// Arms the interleaving for claiming: the next claim of the watched key runs this, once, after the
    /// claim has been decided and before its caller continues.
    /// </summary>
    public void OnNextClaimOf(Func<Task> other) => _onClaim = other;

    /// <inheritdoc />
    public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
        => inner.SetAsync(key, value, options, token);

    /// <inheritdoc />
    public async Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
    {
        var read = await inner.GetAsync<T>(key, removeOnRetrieval, token);

        if (key == watched && Interlocked.Exchange(ref _onRead, null) is { } other)
            await other();

        return read;
    }

    /// <inheritdoc />
    public async Task<bool> TrySetIfAbsentAsync<T>(
        string key, T value, StorageOptions options, CancellationToken? token = null)
    {
        var wrote = await inner.TrySetIfAbsentAsync(key, value, options, token);

        if (key == watched && Interlocked.Exchange(ref _onClaim, null) is { } other)
            await other();

        return wrote;
    }

    /// <inheritdoc />
    public Task RemoveAsync(string key, CancellationToken? token = null) => inner.RemoveAsync(key, token);
}
