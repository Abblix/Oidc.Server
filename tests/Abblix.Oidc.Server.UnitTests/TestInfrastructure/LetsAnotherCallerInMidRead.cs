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
/// A storage that, once, runs somebody else's whole cycle in the middle of a read of one named key.
/// </summary>
/// <remarks>
/// This is the interleaving a read-modify-write loses an update on, and the only one: the second caller
/// must finish writing after the first caller has read and before it writes. Firing threads reaches it by
/// luck, so a green run would say nothing about whether the defect is there.
/// <para>
/// Shared rather than nested in one suite, because every flow that reads a record and writes it back needs
/// the same interleaving, and a second copy is a second set of semantics to keep in step.
/// </para>
/// <para>
/// Armed once and disarmed on use, so the second caller's own reads of the same key do not recurse.
/// </para>
/// </remarks>
/// <param name="inner">The storage every call is forwarded to.</param>
/// <param name="watched">The key whose read lets the other caller in.</param>
public sealed class LetsAnotherCallerInMidRead(IEntityStorage inner, string watched) : IEntityStorage
{
    private Func<Task>? _other;

    /// <summary>
    /// Arms the interleaving: the next read of the watched key runs this, once, before answering.
    /// </summary>
    public void OnNextReadOf(Func<Task> other) => _other = other;

    /// <inheritdoc />
    public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
        => inner.SetAsync(key, value, options, token);

    /// <inheritdoc />
    public async Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
    {
        var read = await inner.GetAsync<T>(key, removeOnRetrieval, token);

        if (key == watched && Interlocked.Exchange(ref _other, null) is { } other)
            await other();

        return read;
    }

    /// <inheritdoc />
    public Task RemoveAsync(string key, CancellationToken? token = null) => inner.RemoveAsync(key, token);
}
