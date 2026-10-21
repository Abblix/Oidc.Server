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
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages;

/// <summary>
/// A cutoff <see cref="RevocationCutoffRegistry"/> records only moves forward, over the in-box storage: a call
/// naming an earlier moment, a retry or a slower concurrent call, never moves it back.
/// </summary>
public class RevocationCutoffRegistryTests
{
    private const string Principal = "subject";

    private static readonly DateTimeOffset Earlier = new(2026, 10, 21, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Later = Earlier.AddHours(3);
    private static readonly DateTimeOffset ExpiresAt = Later.AddDays(30);

    private readonly IEntityStorageKeyFactory _keys = new EntityStorageKeyFactory();
    private readonly IEntityStorage _storage = new DistributedCacheStorage(
        new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
        new ProtobufSerializer());

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private string Key => _keys.RevocationCutoffKey(RevocationScope.Subject, Principal);

    private RevocationCutoffRegistry Registry(IEntityStorage? storage = null) => new(storage ?? _storage, _keys);

    private Task<DateTimeOffset?> CutoffAsync() => Registry().GetCutoffAsync(RevocationScope.Subject, Principal, Ct);

    [Fact]
    public async Task A_first_cutoff_is_recorded()
    {
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct);

        Assert.Equal(Earlier, await CutoffAsync());
    }

    [Fact]
    public async Task A_later_cutoff_replaces_an_earlier_one()
    {
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct);
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct);

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// A retry of an older revocation, arriving after a newer one, changes nothing.
    /// </summary>
    [Fact]
    public async Task An_earlier_cutoff_arriving_later_changes_nothing()
    {
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct);
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct);

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// The earlier call found the record empty, and the later one recorded its cutoff before the earlier call
    /// wrote: the earlier call does not write over it.
    /// </summary>
    [Fact]
    public async Task An_earlier_cutoff_racing_a_later_one_into_an_empty_record_leaves_the_later()
    {
        var racing = new LetsAnotherCallerIn(_storage, Key);
        racing.OnNextReadOf(() => Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct));

        await Registry(racing).SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct);

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// The earlier call read an older cutoff, and the later one replaced it before the earlier call wrote: the
    /// earlier call does not write over it.
    /// </summary>
    [Fact]
    public async Task An_earlier_cutoff_racing_a_later_one_over_an_older_record_leaves_the_later()
    {
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier.AddHours(-1), ExpiresAt, Ct);
        var racing = new LetsAnotherCallerIn(_storage, Key);
        racing.OnNextReadOf(() => Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct));

        await Registry(racing).SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct);

        Assert.Equal(Later, await CutoffAsync());
    }

    /// <summary>
    /// The later call read an older cutoff, and an earlier one, still newer than what was read, was recorded before
    /// the later call wrote: the later call reads again and records its own.
    /// </summary>
    [Fact]
    public async Task A_later_cutoff_racing_an_earlier_one_is_recorded()
    {
        await Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier.AddHours(-1), ExpiresAt, Ct);
        var racing = new LetsAnotherCallerIn(_storage, Key);
        racing.OnNextReadOf(() => Registry().SetCutoffAsync(RevocationScope.Subject, Principal, Earlier, ExpiresAt, Ct));

        await Registry(racing).SetCutoffAsync(RevocationScope.Subject, Principal, Later, ExpiresAt, Ct);

        Assert.Equal(Later, await CutoffAsync());
    }
}
