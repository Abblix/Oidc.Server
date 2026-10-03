// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

public class TenantManagerTests
{
    /// <summary>
    /// A store of tenants in memory that writes only while the version a change names is the one it holds, and can
    /// be told to lose the race to another instance once.
    /// </summary>
    private sealed class MemoryStore : ITenantStore, ITenantStoreWriter
    {
        private readonly Dictionary<string, StoredTenant> _tenants = new(StringComparer.Ordinal);
        private int _versions;

        private int _listings;
        private TaskCompletionSource? _holdNext;

        /// <summary>Whether the next write finds the store changed by another instance since it was read.</summary>
        public bool ChangedMeanwhile { get; set; }

        /// <summary>Held back until released, every listing waits on it while it is set.</summary>
        public TaskCompletionSource? Hold { get; set; }

        /// <summary>How many of the next listings fail, as a store that does not answer.</summary>
        public int FailingListings { get; set; }

        /// <summary>Has the next listing alone wait for <paramref name="hold"/>.</summary>
        public void HoldNextListing(TaskCompletionSource hold) => Volatile.Write(ref _holdNext, hold);

        /// <summary>Run once a write has landed, as what happens to the caller meanwhile.</summary>
        public Action? AfterWrite { get; set; }

        public int Listings => Volatile.Read(ref _listings);

        public IReadOnlyCollection<StoredTenant> Tenants => [.._tenants.Values];

        public async Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _listings);
            if (Hold is { } hold)
                await hold.Task;

            if (Interlocked.Exchange(ref _holdNext, null) is { } holdNext)
                await holdNext.Task;

            if (FailingListings > 0)
            {
                FailingListings--;
                throw new InvalidOperationException("the store of tenants did not answer this once");
            }

            return Tenants;
        }

        public Task<string?> AddAsync(TenantDefinition tenant, CancellationToken cancellationToken)
        {
            if (TakeChangedMeanwhile() || _tenants.ContainsKey(tenant.Id))
                return Task.FromResult<string?>(null);

            return Task.FromResult<string?>(Store(tenant));
        }

        public Task<string?> UpdateAsync(
            TenantDefinition tenant,
            string expectedVersion,
            CancellationToken cancellationToken)
            => Task.FromResult(TakeChangedMeanwhile() || !Holds(tenant.Id, expectedVersion) ? null : Store(tenant));

        public Task<bool> RemoveAsync(string tenantId, string expectedVersion, CancellationToken cancellationToken)
            => Task.FromResult(
                !TakeChangedMeanwhile() && Holds(tenantId, expectedVersion) && _tenants.Remove(tenantId));

        private bool Holds(string tenantId, string version)
            => _tenants.TryGetValue(tenantId, out var held) && held.Version == version;

        private string Store(TenantDefinition tenant)
        {
            var version = (++_versions).ToString(CultureInfo.InvariantCulture);
            _tenants[tenant.Id] = new StoredTenant(tenant, version);
            AfterWrite?.Invoke();
            return version;
        }

        private bool TakeChangedMeanwhile()
        {
            var changed = ChangedMeanwhile;
            ChangedMeanwhile = false;
            return changed;
        }
    }

    private readonly MemoryStore _store = new();
    private readonly StoreTenantCatalog _catalog;
    private readonly TenantManager _manager;

    public TenantManagerTests()
    {
        var options = Options.Create(new MultiTenancyOptions());
        _catalog = new StoreTenantCatalog(
            NullLogger<StoreTenantCatalog>.Instance,
            _store,
            [new TenantDefinitionsCheck()],
            [],
            options,
            new FakeTimeProvider());
        _manager = new TenantManager(
            NullLogger<TenantManager>.Instance,
            _store,
            [new TenantDefinitionsCheck()],
            _catalog,
            _store);
    }

    private static TenantDefinition Tenant(string id, string issuer) => new() { Id = id, Issuer = issuer };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static StoredTenant Stored(Result<StoredTenant, TenantChangeRefusal> result)
        => result.TryGetSuccess(out var stored) ? stored : throw new Xunit.Sdk.XunitException(result.ToString());

    private static TenantChangeRefusalReason Refused(Result<StoredTenant, TenantChangeRefusal> result)
        => result.TryGetFailure(out var refusal)
            ? refusal.Reason
            : throw new Xunit.Sdk.XunitException(result.ToString());

    /// <summary>
    /// A tenant created through the manager is stored under a generation of its own and served at once, without
    /// waiting for the next reading of the store.
    /// </summary>
    [Fact]
    public async Task ACreatedTenant_IsStoredUnderAGenerationOfItsOwn_AndServedAtOnce()
    {
        await _catalog.RefreshAsync(Ct);

        var created = Stored(await _manager.CreateAsync(Tenant("acme", "https://acme.example.com"), Ct));

        Assert.NotEmpty(created.Tenant.Generation);
        Assert.Equal(created, Assert.Single(_store.Tenants));
        Assert.Equal(created.Tenant.Generation, (await _catalog.FindByIdAsync("acme", Ct))?.Generation);
    }

    /// <summary>
    /// A tenant created again under the id of one removed is a new creation, under a generation of its own.
    /// </summary>
    [Fact]
    public async Task ATenantCreatedAgain_HasANewGeneration()
    {
        var first = Stored(await _manager.CreateAsync(Tenant("acme", "https://acme.example.com"), Ct));
        Stored(await _manager.RemoveAsync("acme", first.Version, Ct));

        var second = Stored(await _manager.CreateAsync(Tenant("acme", "https://acme.example.com"), Ct));

        Assert.NotEqual(first.Tenant.Generation, second.Tenant.Generation);
    }

    /// <summary>
    /// A tenant the startup checks would refuse is refused and not stored.
    /// </summary>
    [Fact]
    public async Task ATenantTheChecksRefuse_IsNotStored()
    {
        Stored(await _manager.CreateAsync(Tenant("acme", "https://auth.example.com"), Ct));

        var claimingTheSameAddress = await _manager.CreateAsync(Tenant("globex", "https://auth.example.com"), Ct);

        Assert.Equal(TenantChangeRefusalReason.Invalid, Refused(claimingTheSameAddress));
        Assert.Single(_store.Tenants);
    }

    /// <summary>
    /// A tenant under an id the store holds already is refused as such, whatever else is wrong with it, whether the
    /// manager finds it or the store does.
    /// </summary>
    [Fact]
    public async Task ATenantUnderAnIdHeldAlready_IsRefused()
    {
        Stored(await _manager.CreateAsync(Tenant("acme", "https://acme.example.com"), Ct));
        Stored(await _manager.CreateAsync(Tenant("globex", "https://globex.example.com"), Ct));

        // Claiming globex's address too, which the checks would refuse on their own
        var again = await _manager.CreateAsync(Tenant("acme", "https://globex.example.com"), Ct);
        _store.ChangedMeanwhile = true;
        var lost = await _manager.CreateAsync(Tenant("initech", "https://initech.example.com"), Ct);

        Assert.Equal(TenantChangeRefusalReason.AlreadyExists, Refused(again));
        Assert.Equal(TenantChangeRefusalReason.AlreadyExists, Refused(lost));
    }

    /// <summary>
    /// A changed tenant keeps its generation and is served changed at once; a change naming a version the store no
    /// longer holds is refused as a conflict, and one of a tenant the store does not hold as not found.
    /// </summary>
    [Fact]
    public async Task AChange_KeepsTheGeneration_AndNamesTheVersionItWasReadAt()
    {
        var created = Stored(await _manager.CreateAsync(Tenant("acme", "https://acme.example.com"), Ct));

        var changed = Stored(await _manager.UpdateAsync(
            Tenant("acme", "https://acme.example.com/changed"), created.Version, Ct));
        var stale = await _manager.UpdateAsync(Tenant("acme", "https://acme.example.com"), created.Version, Ct);
        var missing = await _manager.UpdateAsync(Tenant("globex", "https://globex.example.com"), "1", Ct);

        Assert.Equal(created.Tenant.Generation, changed.Tenant.Generation);
        Assert.Equal("https://acme.example.com/changed", (await _catalog.FindByIdAsync("acme", Ct))?.Issuer);
        Assert.Equal(TenantChangeRefusalReason.Conflict, Refused(stale));
        Assert.Equal(TenantChangeRefusalReason.NotFound, Refused(missing));
    }

    /// <summary>
    /// A change another instance overtakes between the read and the write is refused as a conflict.
    /// </summary>
    [Fact]
    public async Task AChangeOvertakenByAnotherInstance_IsAConflict()
    {
        var created = Stored(await _manager.CreateAsync(Tenant("acme", "https://acme.example.com"), Ct));

        _store.ChangedMeanwhile = true;
        var overtaken = await _manager.UpdateAsync(
            Tenant("acme", "https://acme.example.com/changed"), created.Version, Ct);
        _store.ChangedMeanwhile = true;
        var removalOvertaken = await _manager.RemoveAsync("acme", created.Version, Ct);

        Assert.Equal(TenantChangeRefusalReason.Conflict, Refused(overtaken));
        Assert.Equal(TenantChangeRefusalReason.Conflict, Refused(removalOvertaken));
    }

    /// <summary>
    /// A removed tenant is no longer served at once.
    /// </summary>
    [Fact]
    public async Task ARemovedTenant_IsNoLongerServed()
    {
        var created = Stored(await _manager.CreateAsync(Tenant("acme", "https://acme.example.com"), Ct));

        Stored(await _manager.RemoveAsync("acme", created.Version, Ct));

        Assert.Null(await _catalog.FindByIdAsync("acme", Ct));
        Assert.Empty(_store.Tenants);
    }

    /// <summary>
    /// A refusal the checks hold against another tenant the store holds already does not stop an unrelated change.
    /// </summary>
    [Fact]
    public async Task ARefusalOfAnotherTenant_DoesNotStopAChange()
    {
        await _store.AddAsync(Tenant("acme", "https://auth.example.com"), Ct);
        await _store.AddAsync(Tenant("globex", "https://auth.example.com"), Ct);

        var created = Stored(await _manager.CreateAsync(Tenant("initech", "https://initech.example.com"), Ct));

        Assert.Equal("initech", created.Tenant.Id);
    }

    /// <summary>
    /// A change is in the store once written, so a caller giving up afterwards is told it was made rather than led
    /// to retry it, and this instance serves it all the same.
    /// </summary>
    [Fact]
    public async Task ACallerGivingUpAfterTheWrite_IsToldTheChangeWasMade()
    {
        using var giveUp = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        _store.AfterWrite = giveUp.Cancel;

        var created = Stored(await _manager.CreateAsync(Tenant("acme", "https://acme.example.com"), giveUp.Token));

        Assert.Equal(created.Tenant.Generation, (await _catalog.FindByIdAsync("acme", Ct))?.Generation);
    }

    /// <summary>
    /// A reading that fails after the change was written does not undo the change, so the caller is told it was
    /// made, and the catalog's next reading serves it.
    /// </summary>
    [Fact]
    public async Task AReadingThatFailsAfterTheWrite_IsToldTheChangeWasMade()
    {
        await _catalog.RefreshAsync(Ct);
        _store.AfterWrite = () => _store.FailingListings = 1;
        var logged = new List<EventId>();
        var logger = new Moq.Mock<ILogger<TenantManager>>();
        logger.Setup(l => l.IsEnabled(Moq.It.IsAny<LogLevel>())).Returns(true);
        logger
            .Setup(l => l.Log(
                Moq.It.IsAny<LogLevel>(),
                Moq.It.IsAny<EventId>(),
                Moq.It.IsAny<Moq.It.IsAnyType>(),
                Moq.It.IsAny<Exception?>(),
                (Func<Moq.It.IsAnyType, Exception?, string>)Moq.It.IsAny<object>()))
            .Callback((LogLevel _, EventId eventId, object _, Exception? _, Delegate _) => logged.Add(eventId));
        var manager = new TenantManager(logger.Object, _store, [new TenantDefinitionsCheck()], _catalog, _store);

        Stored(await manager.CreateAsync(Tenant("acme", "https://acme.example.com"), Ct));
        Assert.Null(await _catalog.FindByIdAsync("acme", Ct));
        Assert.Equal(LogEvents.MultiTenancy.TenantManager.ChangeNotServedYet, Assert.Single(logged).Id);

        await _catalog.RefreshAsync(Ct);
        Assert.NotNull(await _catalog.FindByIdAsync("acme", Ct));
    }

    /// <summary>
    /// A reading after the write that does not end holds neither the caller, who is told the change was made once
    /// it stops waiting, nor the next change of the instance, which lists the store for itself.
    /// </summary>
    [Fact]
    public async Task AReadingThatDoesNotEnd_HoldsNeitherTheCallerNorTheNextChange()
    {
        var hanging = new TaskCompletionSource();
        _store.AfterWrite = () => _store.HoldNextListing(hanging);

        using var first = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        first.CancelAfter(TimeSpan.FromMilliseconds(100));
        Stored(await _manager.CreateAsync(Tenant("acme", "https://acme.example.com"), first.Token));

        _store.AfterWrite = null;
        using var second = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        second.CancelAfter(TimeSpan.FromMilliseconds(100));
        Stored(await _manager.CreateAsync(Tenant("globex", "https://globex.example.com"), second.Token));

        hanging.SetResult();
        Assert.Equal(2, _store.Tenants.Count);
    }

    /// <summary>
    /// Two changes made on one instance at once are made one after the other, so the second is judged against what
    /// the first left: a tenant moved to an address and another created there at the same moment do not both land
    /// and leave the address to neither.
    /// </summary>
    [Fact]
    public async Task TwoChangesAtOnce_AreMadeOneAfterTheOther()
    {
        var acme = Stored(await _manager.CreateAsync(Tenant("acme", "https://acme.example.com"), Ct));
        var hold = new TaskCompletionSource();
        _store.Hold = hold;
        var listed = _store.Listings;

        var moving = _manager.UpdateAsync(Tenant("acme", "https://shared.example.com"), acme.Version, Ct);
        var creating = _manager.CreateAsync(Tenant("globex", "https://shared.example.com"), Ct);

        // Each change that may read the store now reads it before either is let go
        for (var waited = 0; _store.Listings < listed + 2 && waited < 20; waited++)
            await Task.Delay(TimeSpan.FromMilliseconds(10), Ct);

        _store.Hold = null;
        hold.SetResult();
        var results = await Task.WhenAll(moving, creating);

        Assert.Single(results, result => result.TryGetFailure(out var refusal)
                                         && refusal.Reason == TenantChangeRefusalReason.Invalid);
    }

    /// <summary>
    /// The checks a host adds are asked of each change, as the catalog asks them of each reading.
    /// </summary>
    [Fact]
    public async Task AHostsOwnCheck_IsAskedOfAChange()
    {
        var refusingAcme = new Moq.Mock<ITenantsCheck>();
        refusingAcme
            .Setup(check => check.Check(Moq.It.IsAny<IReadOnlyCollection<TenantDefinition>>()))
            .Returns((IReadOnlyCollection<TenantDefinition> tenants) =>
                tenants.Where(tenant => tenant.Id == "acme").Select(tenant => TenantRefusal.Of(tenant, "not acme")));
        var manager = new TenantManager(
            NullLogger<TenantManager>.Instance,
            _store,
            [new TenantDefinitionsCheck(), refusingAcme.Object],
            _catalog,
            _store);

        var refused = await manager.CreateAsync(Tenant("acme", "https://acme.example.com"), Ct);

        Assert.Equal(TenantChangeRefusalReason.Invalid, Refused(refused));
        Assert.Empty(_store.Tenants);
    }

    /// <summary>
    /// A store without a writer cannot be changed through the manager, and says why.
    /// </summary>
    [Fact]
    public async Task AStoreWithoutAWriter_IsRefused()
    {
        var manager = new TenantManager(
            NullLogger<TenantManager>.Instance,
            _store,
            [new TenantDefinitionsCheck()],
            _catalog);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => manager.CreateAsync(Tenant("acme", "https://acme.example.com"), Ct));
    }
}
