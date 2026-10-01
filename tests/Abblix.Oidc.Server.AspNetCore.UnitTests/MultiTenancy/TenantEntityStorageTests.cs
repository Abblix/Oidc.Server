// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// Entities written under one tenant, as <see cref="TenantEntityStorage"/> keeps them apart from every other.
/// </summary>
public class TenantEntityStorageTests
{
    private static readonly StorageOptions Options = new() { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1) };

    /// <summary>The tenant the storage is asked under, switched by the test as a request would switch it.</summary>
    private sealed class SwitchableTenantAccessor : ITenantAccessor
    {
        public TenantContext? Current { get; set; }

        public void Enter(string? id, string generation = "") => Current = id is null
            ? null
            : new TenantContext
            {
                Tenant = new TenantDefinition
                {
                    Id = id,
                    Issuer = $"https://auth.example.com/tenants/{id}",
                    Generation = generation,
                },
            };
    }

    /// <summary>An inner storage that remembers every key it was handed, as the distributed cache would.</summary>
    private sealed class DictionaryStorage : IEntityStorage
    {
        public ConcurrentDictionary<string, object?> Entries { get; } = new();

        public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
        {
            Entries[key] = value;
            return Task.CompletedTask;
        }

        public Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
        {
            var found = removeOnRetrieval ? Entries.TryRemove(key, out var value) : Entries.TryGetValue(key, out value);
            return Task.FromResult(found ? (T?)value : default);
        }

        public Task<bool> TrySetIfAbsentAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
            => Task.FromResult(Entries.TryAdd(key, value));

        public Task RemoveAsync(string key, CancellationToken? token = null)
        {
            Entries.TryRemove(key, out _);
            return Task.CompletedTask;
        }
    }

    private readonly SwitchableTenantAccessor _tenant = new();
    private readonly DictionaryStorage _inner = new();

    private TenantEntityStorage Storage => new(_inner, _tenant);

    [Fact]
    public async Task AnEntityWrittenUnderOneTenant_IsNotReadUnderAnother()
    {
        _tenant.Enter("acme");
        await Storage.SetAsync("Grant:code-1", "acme's grant", Options);

        _tenant.Enter("globex");
        Assert.Null(await Storage.GetAsync<string>("Grant:code-1", removeOnRetrieval: true));

        _tenant.Enter("acme");
        Assert.Equal("acme's grant", await Storage.GetAsync<string>("Grant:code-1", removeOnRetrieval: true));
    }

    /// <summary>
    /// A key claimed under one tenant is still free under another, and removing it under one leaves the other's.
    /// </summary>
    [Fact]
    public async Task ClaimAndRemove_ActOnlyWithinTheTenant()
    {
        _tenant.Enter("acme");
        Assert.True(await Storage.TrySetIfAbsentAsync("UserCode:ABCD", 1, Options));

        _tenant.Enter("globex");
        Assert.True(await Storage.TrySetIfAbsentAsync("UserCode:ABCD", 2, Options));
        await Storage.RemoveAsync("UserCode:ABCD");

        _tenant.Enter("acme");
        Assert.False(await Storage.TrySetIfAbsentAsync("UserCode:ABCD", 3, Options));
        Assert.Equal(1, await Storage.GetAsync<int>("UserCode:ABCD", removeOnRetrieval: false));
    }

    /// <summary>
    /// An id may hold the separator, so the id and the key must not run together: tenant <c>a</c> with key
    /// <c>b:x</c> and tenant <c>a:b</c> with key <c>x</c> are two entries.
    /// </summary>
    [Fact]
    public async Task ATenantIdHoldingTheSeparator_DoesNotRunIntoTheKey()
    {
        _tenant.Enter("a");
        await Storage.SetAsync("b:x", "a's", Options);

        _tenant.Enter("a:b");
        Assert.Null(await Storage.GetAsync<string>("x", removeOnRetrieval: false));
        Assert.Single(_inner.Entries);
    }

    /// <summary>
    /// A tenant created again under the id of one removed is another generation, and reads nothing the removed one
    /// stored: a code or a refresh token issued before the removal is not redeemed by whoever holds the id next.
    /// </summary>
    [Fact]
    public async Task ATenantCreatedAgainUnderAnId_ReadsNothingTheFormerOneStored()
    {
        _tenant.Enter("acme", generation: "1");
        await Storage.SetAsync("code", "the former tenant's", Options);

        _tenant.Enter("acme", generation: "2");
        Assert.Null(await Storage.GetAsync<string>("code", removeOnRetrieval: false));
    }

    /// <summary>
    /// A tenant the settings declare has no generation and keeps the key form it had before generations, so what
    /// it stored before an upgrade is still its own; one with a generation cannot spell that key.
    /// </summary>
    [Fact]
    public async Task ATenantWithoutAGeneration_KeepsTheKeyItHadBefore()
    {
        _tenant.Enter("acme");
        await Storage.SetAsync("code", "acme's", Options);

        Assert.Equal("tenant:4:acme:code", Assert.Single(_inner.Entries).Key);
        _tenant.Enter("acme", generation: "code");
        Assert.Null(await Storage.GetAsync<string>(string.Empty, removeOnRetrieval: false));
    }

    /// <summary>
    /// Without a tenant there is no space to keep the entity in: writing it into a shared one is the leak this
    /// storage exists to prevent.
    /// </summary>
    [Fact]
    public async Task WithoutATenant_EveryOperationIsRefused()
    {
        _tenant.Enter(null);

        await Assert.ThrowsAsync<InvalidOperationException>(() => Storage.SetAsync("k", 1, Options));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Storage.GetAsync<int>("k", removeOnRetrieval: false));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Storage.TrySetIfAbsentAsync("k", 1, Options));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Storage.RemoveAsync("k"));
        Assert.Empty(_inner.Entries);
    }
}
