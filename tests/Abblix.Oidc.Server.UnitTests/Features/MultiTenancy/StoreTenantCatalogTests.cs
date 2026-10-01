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

        public async Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
        {
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

    private const string Version = "1";

    private readonly FakeStore _store = new();
    private readonly RecordingLogger _logger = new();

    private StoreTenantCatalog Catalog() => new(_logger, _store, [new TenantDefinitionsCheck()]);

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
    /// An id the store holds twice names no one tenant, so neither is served, whatever checks the host keeps; the
    /// other tenants are.
    /// </summary>
    [Fact]
    public async Task AnIdHeldTwice_IsNotServed_WhateverTheChecks()
    {
        var ct = TestContext.Current.CancellationToken;
        _store.Tenants.Add(Stored("acme", "https://acme.example.com"));
        _store.Tenants.Add(Stored("acme", "https://acme2.example.com"));
        _store.Tenants.Add(Stored("globex", "https://globex.example.com"));
        var catalog = new StoreTenantCatalog(_logger, _store, []);

        await catalog.RefreshAsync(ct);

        Assert.Null(await catalog.FindByIdAsync("acme", ct));
        Assert.NotNull(await catalog.FindByIdAsync("globex", ct));
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
