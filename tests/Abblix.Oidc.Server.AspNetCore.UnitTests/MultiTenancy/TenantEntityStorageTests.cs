// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Tests.Shared;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using Xunit;


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
                    Issuer = new Uri($"https://auth.example.com/tenants/{id}"),
                    Generation = generation,
                },
            };
    }

    private readonly SwitchableTenantAccessor _tenant = new();
    private readonly Mock<IEntityStorage> _inner = EntityStorageMock.Over(new DistributedCacheStorage(
        new MemoryDistributedCache(Microsoft.Extensions.Options.Options.Create(new MemoryDistributedCacheOptions())),
        new JsonBinarySerializer()));

    private TenantEntityStorage Storage => new(_inner.Object, _tenant);

    /// <summary>
    /// The keys written to the storage underneath, which is where a tenant's key form is seen.
    /// </summary>
    private string[] WrittenKeys() => _inner.Invocations
        .Where(invocation => invocation.Method.Name == nameof(IEntityStorage.SetAsync))
        .Select(invocation => (string)invocation.Arguments[0])
        .Distinct()
        .ToArray();

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
    /// An entry written under one tenant is not found to keep longer under another.
    /// </summary>
    [Fact]
    public async Task Extending_ActsOnlyWithinTheTenant()
    {
        _tenant.Enter("acme");
        await Storage.SetAsync("SessionClient:s", "acme's", Options);

        _tenant.Enter("globex");
        Assert.False(await Storage.TryExtendAsync("SessionClient:s", Options));

        _tenant.Enter("acme");
        Assert.True(await Storage.TryExtendAsync("SessionClient:s", Options));
    }

    /// <summary>
    /// An entry written under one tenant is not replaced under another, even by a caller holding its value.
    /// </summary>
    [Fact]
    public async Task Replacing_ActsOnlyWithinTheTenant()
    {
        _tenant.Enter("acme");
        await Storage.SetAsync("Cutoff:s", "acme's", Options);

        _tenant.Enter("globex");
        Assert.False(await Storage.TryReplaceAsync("Cutoff:s", "acme's", "globex's", Options));

        _tenant.Enter("acme");
        Assert.Equal("acme's", await Storage.GetAsync<string>("Cutoff:s", removeOnRetrieval: false));
        Assert.True(await Storage.TryReplaceAsync("Cutoff:s", "acme's", "acme's later", Options));
        Assert.Equal("acme's later", await Storage.GetAsync<string>("Cutoff:s", removeOnRetrieval: false));
    }

    /// <summary>
    /// A tenant served by a catalog of the host's own passes none of the server's checks, so one whose id or
    /// generation could spell another tenant's space - tenant <c>a:b</c> with key <c>x</c> reading what tenant
    /// <c>a</c> wrote under <c>b:x</c> - stores and reads nothing.
    /// </summary>
    [Theory]
    [InlineData("a:b", "")]
    [InlineData("acme~2", "")]
    [InlineData("acme.eu", "")]
    [InlineData("acme eu", "")]
    [InlineData("münchen", "")]
    [InlineData("acme", "2:x")]
    [InlineData("acme", "2~x")]
    public async Task ATenantThatCannotNameItsSpace_StoresAndReadsNothing(string id, string generation)
    {
        _tenant.Enter(id, generation);

        await Assert.ThrowsAsync<InvalidOperationException>(() => Storage.SetAsync("x", "value", Options));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Storage.GetAsync<string>("x", removeOnRetrieval: false));
        Assert.Empty(_inner.Invocations);
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
    /// A key reads as the tenant's id, its generation when it has one, and the key, so an operator looking at the
    /// storage tells whose entry it is.
    /// </summary>
    [Theory]
    [InlineData("acme", "", "tenant:acme:code")]
    [InlineData("acme-eu_1", "", "tenant:acme-eu_1:code")]
    [InlineData("acme", "2f9c", "tenant:acme~2f9c:code")]
    public async Task AKey_NamesTheTenantAndItsGeneration(string id, string generation, string expected)
    {
        _tenant.Enter(id, generation);
        await Storage.SetAsync("code", "acme's", Options);

        Assert.Equal(expected, Assert.Single(WrittenKeys()));
    }

    /// <summary>
    /// A generation must not run into the key of a tenant without one: tenant <c>acme</c> with key <c>4:code:x</c>
    /// and tenant <c>acme</c> of generation <c>code</c> with key <c>x</c> are two entries.
    /// </summary>
    [Fact]
    public async Task AGeneration_DoesNotRunIntoTheKeyOfATenantWithoutOne()
    {
        _tenant.Enter("acme");
        await Storage.SetAsync("4:code:x", "acme's", Options);

        _tenant.Enter("acme", generation: "code");
        Assert.Null(await Storage.GetAsync<string>("x", removeOnRetrieval: false));
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
        await Assert.ThrowsAsync<InvalidOperationException>(() => Storage.TryReplaceAsync("k", 1, 2, Options));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Storage.TryExtendAsync("k", Options));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Storage.RemoveAsync("k"));
        Assert.Empty(_inner.Invocations);
    }
}
