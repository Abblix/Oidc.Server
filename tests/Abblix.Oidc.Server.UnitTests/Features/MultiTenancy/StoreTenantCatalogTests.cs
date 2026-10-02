// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

/// <summary>
/// The tenants a store holds, as the server serves them: what the checks refuse is left out and logged, the rest
/// is served, and a change in the store reaches the server with the next reading.
/// </summary>
public class StoreTenantCatalogTests
{
    /// <summary>
    /// A store whose tenants a test changes between readings, can make unreadable, and can hold the next reading
    /// back until the test lets it answer with what it held when asked.
    /// </summary>
    private sealed class FakeStore : ITenantStore
    {
        public List<StoredTenant> Tenants { get; } = [];

        public Exception? FailWith { get; set; }

        public int FailingReadings { get; set; }

        public TaskCompletionSource? HoldNextReading { get; set; }

        private int _readings;

        public int Readings => Volatile.Read(ref _readings);

        public async Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _readings);
            IReadOnlyCollection<StoredTenant> held = [..Tenants];
            if (HoldNextReading is { } hold)
            {
                HoldNextReading = null;
                await hold.Task;
            }

            if (FailWith is not null)
                throw FailWith;

            if (FailingReadings > 0)
            {
                FailingReadings--;
                throw new InvalidOperationException("the store of tenants did not answer this once");
            }

            return held;
        }
    }

    /// <summary>Counts the records of refused tenants.</summary>
    private sealed class RecordingLogger : ILogger<StoreTenantCatalog>
    {
        public List<string> Errors { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Error)
                Errors.Add(formatter(state, exception));
        }
    }

    /// <summary>
    /// Readies each tenant it is asked to, failing those named in <see cref="Failing"/>, and holds every opening
    /// back while <see cref="Hold"/> is set, as a custodian that does not answer.
    /// </summary>
    private sealed class FakeOpening : ITenantOpening
    {
        public HashSet<string> Failing { get; } = [];

        public TaskCompletionSource? Hold { get; set; }

        public async Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
            IReadOnlyCollection<TenantDefinition> tenants,
            CancellationToken cancellationToken)
        {
            if (Hold is { } hold)
                await hold.Task.WaitAsync(cancellationToken);

            return tenants
                .Where(tenant => Failing.Contains(tenant.Id))
                .ToDictionary(
                    tenant => tenant.Id,
                    Exception (_) => new InvalidOperationException("the tenant's first key could not be minted"));
        }
    }

    private const string Version = "1";

    private readonly FakeStore _store = new();
    private readonly RecordingLogger _logger = new();
    private readonly FakeOpening _opening = new();

    private readonly MultiTenancyOptions _options = new();

    private StoreTenantCatalog Catalog(ITenantStore? store = null) => new(
        _logger,
        store ?? _store,
        [new TenantDefinitionsCheck()],
        [_opening],
        Options.Create(_options));

    private static StoredTenant Stored(string id, string issuer, string version = Version)
        => new(new TenantDefinition { Id = id, Issuer = issuer, Generation = "g1" }, version);

    /// <summary>
    /// A tenant the checks refuse is left out and logged by name, and the others are served.
    /// </summary>
    [Fact]
    public async Task ATenantTheChecksRefuse_IsLeftOut_AndTheOthersServed()
    {
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        _store.Tenants.Add(Stored("broken", "ftp://broken.example.com"));
        var catalog = Catalog();
        var ct = TestContext.Current.CancellationToken;

        await catalog.RefreshAsync(ct);

        Assert.NotNull(await catalog.FindByIdAsync("acme", ct));
        Assert.Null(await catalog.FindByIdAsync("broken", ct));
        Assert.Contains("broken", Assert.Single(_logger.Errors), StringComparison.Ordinal);
    }

    /// <summary>
    /// Every party to a conflict is left out, so every instance reading the store serves the same tenants however
    /// the conflict was written.
    /// </summary>
    [Fact]
    public async Task TwoTenantsAtOneAddress_AreBothLeftOut()
    {
        _store.Tenants.Add(Stored("acme", "https://auth.example.com/tenants/x"));
        _store.Tenants.Add(Stored("globex", "https://auth.example.com/tenants/x"));
        var catalog = Catalog();
        var ct = TestContext.Current.CancellationToken;

        await catalog.RefreshAsync(ct);

        Assert.Null(await catalog.FindByIdAsync("acme", ct));
        Assert.Null(await catalog.FindByIdAsync("globex", ct));
        Assert.Null(await catalog.FindByAddressAsync("auth.example.com", "/tenants/x/token", ct));
    }

    /// <summary>
    /// A refusal standing from one reading to the next is logged once, so a bad row does not fill the log at every
    /// reading.
    /// </summary>
    [Fact]
    public async Task ARefusalStandingAcrossReadings_IsLoggedOnce()
    {
        _store.Tenants.Add(Stored("broken", "ftp://broken.example.com"));
        var catalog = Catalog();
        var ct = TestContext.Current.CancellationToken;

        await catalog.RefreshAsync(ct);
        await catalog.RefreshAsync(ct);

        Assert.Single(_logger.Errors);
    }

    /// <summary>
    /// A tenant the store gains is served after the next reading, and one it loses is no longer found by id or by
    /// address.
    /// </summary>
    [Fact]
    public async Task ANextReading_ServesWhatTheStoreGained_AndDropsWhatItLost()
    {
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        var catalog = Catalog();
        var ct = TestContext.Current.CancellationToken;
        await catalog.RefreshAsync(ct);

        _store.Tenants.Clear();
        _store.Tenants.Add(Stored("globex", "https://globex.example.com"));
        await catalog.RefreshAsync(ct);

        Assert.Null(await catalog.FindByIdAsync("acme", ct));
        Assert.Null(await catalog.FindByAddressAsync("acme.example.com", "/", ct));
        Assert.NotNull(await catalog.FindByAddressAsync("globex.example.com", "/", ct));
    }

    /// <summary>
    /// A tenant the store gains that cannot be readied is left out of that reading and logged while the others are
    /// served, and is served by the first reading that readies it.
    /// </summary>
    [Fact]
    public async Task ATenantThatCannotBeOpened_IsLeftOutAndLogged_UntilAReadingOpensIt()
    {
        var ct = TestContext.Current.CancellationToken;
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        var catalog = Catalog();
        await catalog.RefreshAsync(ct);

        _store.Tenants.Add(Stored("globex", "https://globex.example.com"));
        _opening.Failing.Add("globex");
        await catalog.RefreshAsync(ct);

        Assert.Null(await catalog.FindByIdAsync("globex", ct));
        Assert.NotNull(await catalog.FindByIdAsync("acme", ct));
        await catalog.RefreshAsync(ct);
        Assert.Single(_logger.Errors);

        _opening.Failing.Clear();
        await catalog.RefreshAsync(ct);

        Assert.NotNull(await catalog.FindByIdAsync("globex", ct));
    }

    /// <summary>
    /// A tenant of a store of the host's own that cannot be readied on the reading the server starts with is left
    /// out and logged like any other, so one failing tenant does not stop the server serving the rest.
    /// </summary>
    [Fact]
    public async Task ATenantOfAStoreThatCannotBeOpened_OnTheFirstReading_IsLeftOut()
    {
        var ct = TestContext.Current.CancellationToken;
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        _store.Tenants.Add(Stored("globex", "https://globex.example.com"));
        _opening.Failing.Add("acme");
        var catalog = Catalog();

        await catalog.RefreshAsync(ct);

        Assert.Null(await catalog.FindByIdAsync("acme", ct));
        Assert.NotNull(await catalog.FindByIdAsync("globex", ct));
        Assert.Single(_logger.Errors);
    }

    /// <summary>
    /// A tenant the settings declare that cannot be readied on the reading the server starts with refuses the start,
    /// as the settings would refuse it; the reading is not kept.
    /// </summary>
    [Fact]
    public async Task ATenantTheSettingsDeclare_ThatCannotBeOpened_FailsTheFirstReading()
    {
        var ct = TestContext.Current.CancellationToken;
        var declared = new MultiTenancyOptions
        {
            Tenants = [new TenantDefinition { Id = "acme", Issuer = "https://acme.example.com" }],
        };
        _opening.Failing.Add("acme");
        var catalog = Catalog(new OptionsTenantStore(Options.Create(declared)));

        await Assert.ThrowsAsync<InvalidOperationException>(() => catalog.RefreshAsync(ct));

        _opening.Failing.Clear();
        Assert.NotNull(await catalog.FindByIdAsync("acme", ct));
    }

    /// <summary>
    /// While a tenant new to the catalog is being readied, the changes and removals of the tenants served before
    /// are served already, so a custodian slow to answer holds back only the new tenant.
    /// </summary>
    [Fact]
    public async Task WhileANewTenantIsReadied_ARemovalIsServedAlready()
    {
        var ct = TestContext.Current.CancellationToken;
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        var catalog = Catalog();
        await catalog.RefreshAsync(ct);

        _store.Tenants.Clear();
        _store.Tenants.Add(Stored("globex", "https://globex.example.com"));
        var hold = new TaskCompletionSource();
        _opening.Hold = hold;
        var reading = catalog.RefreshAsync(ct);

        Assert.Null(await catalog.FindByIdAsync("acme", ct));
        Assert.Null(await catalog.FindByIdAsync("globex", ct));

        hold.SetResult();
        await reading;
        Assert.NotNull(await catalog.FindByIdAsync("globex", ct));
    }

    /// <summary>
    /// The openings of one reading may take one refresh period, so a custodian that never answers leaves the new
    /// tenants out of that reading instead of stopping the readings.
    /// </summary>
    [Fact]
    public async Task OpeningsThatDoNotFinishWithinTheRefreshPeriod_LeaveTheNewTenantsOut()
    {
        var ct = TestContext.Current.CancellationToken;
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        _options.RefreshEvery = TimeSpan.FromMilliseconds(1);
        _opening.Hold = new TaskCompletionSource();
        var catalog = Catalog();

        await catalog.RefreshAsync(ct);

        Assert.Null(await catalog.FindByIdAsync("acme", ct));
        Assert.Single(_logger.Errors);
    }

    /// <summary>
    /// A tenant the store holds unchanged keeps the definition served before, so what was built from it is kept;
    /// a new version of it replaces the definition.
    /// </summary>
    [Fact]
    public async Task AnUnchangedTenant_KeepsItsDefinition_AndAChangedOneIsReplaced()
    {
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        var catalog = Catalog();
        var ct = TestContext.Current.CancellationToken;
        await catalog.RefreshAsync(ct);
        var served = await catalog.FindByIdAsync("acme", ct);

        _store.Tenants[0] = Stored("acme", "https://acme.example.com");
        await catalog.RefreshAsync(ct);
        Assert.Same(served, await catalog.FindByIdAsync("acme", ct));

        _store.Tenants[0] = Stored("acme", "https://acme.example.com", version: "2");
        await catalog.RefreshAsync(ct);
        Assert.NotSame(served, await catalog.FindByIdAsync("acme", ct));
    }

    /// <summary>
    /// A reading that fails keeps the tenants of the last one: an outage of the store is not an outage of every
    /// tenant.
    /// </summary>
    [Fact]
    public async Task AFailedReading_KeepsTheTenantsOfTheLastOne()
    {
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        var catalog = Catalog();
        var ct = TestContext.Current.CancellationToken;
        await catalog.RefreshAsync(ct);

        _store.FailWith = new InvalidOperationException("the store of tenants is unreachable");
        await Assert.ThrowsAsync<InvalidOperationException>(() => catalog.RefreshAsync(ct));

        Assert.NotNull(await catalog.FindByIdAsync("acme", ct));
    }

    /// <summary>
    /// A reading begun before a newer one does not replace it: they run one at a time, so a tenant created between
    /// them stays served.
    /// </summary>
    [Fact]
    public async Task AnOlderReading_DoesNotReplaceANewerOne()
    {
        var ct = TestContext.Current.CancellationToken;
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        var catalog = Catalog();
        var release = new TaskCompletionSource();
        _store.HoldNextReading = release;

        var older = catalog.RefreshAsync(ct);
        _store.Tenants.Add(Stored("globex", "https://globex.example.com"));
        var newer = catalog.RefreshAsync(ct);
        release.SetResult();
        await Task.WhenAll(older, newer);

        Assert.NotNull(await catalog.FindByIdAsync("globex", ct));
    }

    /// <summary>
    /// A first reading made on a question and failed is not kept: the next question reads the store again.
    /// </summary>
    [Fact]
    public async Task AFailedFirstReading_IsNotKept()
    {
        var ct = TestContext.Current.CancellationToken;
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        _store.FailingReadings = 1;
        var catalog = Catalog();

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await catalog.FindByIdAsync("acme", ct));
        Assert.NotNull(await catalog.FindByIdAsync("acme", ct));
    }

    /// <summary>
    /// An id the store holds twice, or a tenant with no id, is left out and logged once, reading after reading,
    /// while the other tenants are served.
    /// </summary>
    [Fact]
    public async Task AnIdHeldTwice_OrNone_IsLeftOut_ReadingAfterReading()
    {
        var ct = TestContext.Current.CancellationToken;
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        _store.Tenants.Add(Stored("acme", "https://acme2.example.com"));
        _store.Tenants.Add(Stored(null!, "https://nobody.example.com"));
        _store.Tenants.Add(Stored("globex", "https://globex.example.com"));
        var catalog = Catalog();

        await catalog.RefreshAsync(ct);
        await catalog.RefreshAsync(ct);

        Assert.Null(await catalog.FindByIdAsync("acme", ct));
        Assert.Null(await catalog.FindByAddressAsync("nobody.example.com", "/", ct));
        Assert.NotNull(await catalog.FindByIdAsync("globex", ct));
        Assert.Equal(2, _logger.Errors.Count);
    }

    /// <summary>
    /// Questions arriving together before anything read the store wait for one reading rather than each make
    /// their own.
    /// </summary>
    [Fact]
    public async Task QuestionsArrivingBeforeAnyReading_ShareOne()
    {
        var ct = TestContext.Current.CancellationToken;
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        var release = new TaskCompletionSource();
        _store.HoldNextReading = release;
        var catalog = Catalog();

        var first = AskAsync();
        var second = AskAsync();
        release.SetResult();
        await Task.WhenAll(first, second);

        Assert.Equal(1, _store.Readings);

        async Task<TenantDefinition?> AskAsync() => await catalog.FindByIdAsync("acme", ct);
    }

    /// <summary>
    /// Asked before anything refreshed it, as in a container no host started, the catalog reads the store once
    /// itself.
    /// </summary>
    [Fact]
    public async Task AskedBeforeAnyReading_TheCatalogReadsTheStore()
    {
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));

        Assert.NotNull(await Catalog().FindByIdAsync("acme", TestContext.Current.CancellationToken));
    }
}
