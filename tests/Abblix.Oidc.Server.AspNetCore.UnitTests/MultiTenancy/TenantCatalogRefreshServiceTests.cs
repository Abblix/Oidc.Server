// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// The server reads the store of tenants before serving and again every period, and an outage of the store after
/// startup costs only how current the tenants are.
/// </summary>
public class TenantCatalogRefreshServiceTests
{
    private static readonly TimeSpan Period = TimeSpan.FromMinutes(1);

    /// <summary>How long a wait on the refresh loop's thread sleeps between looks.</summary>
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(50);

    private const int MaxPolls = 100;

    /// <summary>A store whose tenants a test changes between readings, and can make unreadable.</summary>
    private sealed class FakeStore : ITenantStore
    {
        private int _readings;

        public List<StoredTenant> Tenants { get; } = [];

        public Exception? FailWith { get; set; }

        public int Readings => Volatile.Read(ref _readings);

        public Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _readings);
            return FailWith is null
                ? Task.FromResult<IReadOnlyCollection<StoredTenant>>([..Tenants])
                : Task.FromException<IReadOnlyCollection<StoredTenant>>(FailWith);
        }
    }

    /// <summary>Counts the errors the service records.</summary>
    private sealed class RecordingLogger : ILogger<TenantCatalogRefreshService>
    {
        private int _errors;

        public int Errors => Volatile.Read(ref _errors);

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Error)
                Interlocked.Increment(ref _errors);
        }
    }

    private readonly FakeStore _store = new();
    private readonly FakeTimeProvider _time = new();
    private readonly RecordingLogger _logger = new();
    private readonly StoreTenantCatalog _catalog;

    public TenantCatalogRefreshServiceTests()
    {
        _catalog = new StoreTenantCatalog(NullLogger<StoreTenantCatalog>.Instance, _store, []);
    }

    private TenantCatalogRefreshService Service(ITenantCatalog? served = null)
        => new(
            _logger,
            _catalog,
            served ?? _catalog,
            Options.Create(new MultiTenancyOptions { RefreshEvery = Period }),
            _time);

    private static StoredTenant Stored(string id)
        => new(new TenantDefinition { Id = id, Issuer = $"https://{id}.example.com" }, "1");

    /// <summary>
    /// A store that cannot be read at startup stops the process: there is nobody yet to serve.
    /// </summary>
    [Fact]
    public async Task AStoreUnreadableAtStartup_StopsTheServer()
    {
        _store.FailWith = new InvalidOperationException("the store of tenants is unreachable");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Service().StartAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Every period the store is read again, so a tenant it gained is served without a restart.
    /// </summary>
    [Fact]
    public async Task EveryPeriod_TheStoreIsReadAgain()
    {
        var ct = TestContext.Current.CancellationToken;
        _store.Tenants.Add(Stored("acme"));
        var service = Service();
        await service.StartAsync(ct);

        _store.Tenants.Add(Stored("globex"));
        await AdvanceUntilReadAsync(_store.Readings + 1);

        Assert.NotNull(await _catalog.FindByIdAsync("globex", ct));
        await service.StopAsync(ct);
    }

    /// <summary>
    /// A reading that fails after startup is logged and leaves the tenants of the last one served, and the next
    /// period reads again.
    /// </summary>
    [Fact]
    public async Task AFailedReadingAfterStartup_IsLogged_AndTheTenantsStayServed()
    {
        var ct = TestContext.Current.CancellationToken;
        _store.Tenants.Add(Stored("acme"));
        var service = Service();
        await service.StartAsync(ct);

        _store.FailWith = new InvalidOperationException("the store of tenants is unreachable");
        await AdvanceUntilReadAsync(_store.Readings + 2);
        for (var polls = 0; _logger.Errors < 2 && polls < MaxPolls; polls++)
            await Task.Delay(PollInterval, ct);

        Assert.Equal(2, _logger.Errors);
        Assert.NotNull(await _catalog.FindByIdAsync("acme", ct));
        await service.StopAsync(ct);
    }

    /// <summary>
    /// A host serving tenants from a catalog of its own reads no store of tenants, so a store it never meant to
    /// use cannot stop the server.
    /// </summary>
    [Fact]
    public async Task UnderACatalogOfTheHostsOwn_TheStoreIsNotRead()
    {
        _store.FailWith = new InvalidOperationException("the store of tenants is unreachable");

        await Service(served: Moq.Mock.Of<ITenantCatalog>()).StartAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, _store.Readings);
    }

    /// <summary>
    /// Advances the clock a period at a time until the store has been read <paramref name="readings"/> times, so
    /// the test does not race the loop arming its timer.
    /// </summary>
    private async Task AdvanceUntilReadAsync(int readings)
    {
        for (var polls = 0; _store.Readings < readings && polls < MaxPolls; polls++)
        {
            _time.Advance(Period);
            await Task.Delay(PollInterval, TestContext.Current.CancellationToken);
        }

        Assert.True(_store.Readings >= readings, "The store was not read again.");
    }
}
