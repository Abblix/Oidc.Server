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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// How the license counts the addresses of a tenant the server's own catalog serves: the address it is served at now,
/// and one it left no longer than one refresh period ago measured at the catalog's readings, count as the tenant;
/// any other address a definition of it names counts as an issuer of its own.
/// </summary>
[Collection(nameof(LicenseEnforcementTests))]
public sealed class TenantAddressCountTests : IDisposable
{
    private const string A = "https://auth.example.com";
    private const string B = "https://second-issuer.example.com";
    private const string C = "https://third-issuer.example.com";
    private const string G = "https://globex.example.com";
    private const string I = "https://initech.example.com";

    private static readonly TimeSpan Pause = new OidcOptions().RefreshTenantsEvery;

    public TenantAddressCountTests() => TestLicense.ClearChecker();

    public void Dispose() => TestLicense.ResetChecker();

    [Fact]
    public async Task A_definition_entered_after_its_tenant_was_released_takes_a_place_at_each_new_address()
    {
        // A host entering a definition under the id and generation of a creation the catalog has just released, at
        // addresses that creation was never served at, is counted by each address: the release does not let them go
        var ct = TestContext.Current.CancellationToken;
        var listed = new List<StoredTenant> { At("acme", A, "1") };
        var time = new FakeTimeProvider();
        var catalog = Catalog(listed, time);
        await catalog.RefreshAsync(ct);
        var served = (await catalog.FindByIdAsync("acme", ct))!;

        listed.Clear();
        await catalog.RefreshAsync(ct);
        time.Advance(Pause);
        await catalog.RefreshAsync(ct);

        Assert.Equal(B, LicenseChecker.CheckIssuer(B, Settings(catalog, Entered(served, B))));
        var refusal = Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(C, Settings(catalog, Entered(served, C))));
        Assert.Equal(LicenseRefusalReasons.IssuerLimit, refusal.Reason);
    }

    [Fact]
    public async Task An_address_left_counts_by_its_issuer_one_period_after_the_reading_that_moved_the_tenant()
    {
        // The move is read in the same reading that closes another tenant, whose closing takes a while: the period is
        // measured from the reading, as a release found at that reading is
        var ct = TestContext.Current.CancellationToken;
        var listed = new List<StoredTenant> { At("acme", A, "1"), At("globex", G, "1"), At("initech", I, "1") };
        var time = new FakeTimeProvider();
        var closingTakes = TimeSpan.FromSeconds(1);
        var catalog = Catalog(listed, time, new SlowClosing(time, closingTakes));
        await catalog.RefreshAsync(ct);
        var before = (await catalog.FindByIdAsync("acme", ct))!;
        var initech = Settings(catalog, (await catalog.FindByIdAsync("initech", ct))!);
        LicenseChecker.CheckIssuer(A, Settings(catalog, before));

        listed.RemoveAt(1);
        await catalog.RefreshAsync(ct);

        time.Advance(Pause);
        listed.RemoveAt(1);
        listed[0] = At("acme", B, "2");
        await catalog.RefreshAsync(ct);

        time.Advance(Pause - closingTakes);
        await catalog.RefreshAsync(ct);

        Assert.True(initech.Released.IsCancellationRequested);
        var refusal = Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(A, Settings(catalog, before)));
        Assert.Equal(LicenseRefusalReasons.IssuerLimit, refusal.Reason);
    }

    [Fact]
    public async Task A_reading_inside_the_period_does_not_extend_it()
    {
        var ct = TestContext.Current.CancellationToken;
        var listed = new List<StoredTenant> { At("acme", A, "1") };
        var time = new FakeTimeProvider();
        var catalog = Catalog(listed, time);
        await catalog.RefreshAsync(ct);
        var before = (await catalog.FindByIdAsync("acme", ct))!;
        LicenseChecker.CheckIssuer(A, Settings(catalog, before));

        listed[0] = At("acme", B, "2");
        await catalog.RefreshAsync(ct);
        time.Advance(Pause / 2);
        await catalog.RefreshAsync(ct);
        time.Advance(Pause / 2);
        await catalog.RefreshAsync(ct);

        var refusal = Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(A, Settings(catalog, before)));
        Assert.Equal(LicenseRefusalReasons.IssuerLimit, refusal.Reason);
    }

    [Fact]
    public async Task A_tenant_moved_twice_within_one_period_keeps_each_address_for_its_own_period()
    {
        var ct = TestContext.Current.CancellationToken;
        var listed = new List<StoredTenant> { At("acme", A, "1") };
        var time = new FakeTimeProvider();
        var catalog = Catalog(listed, time);
        await catalog.RefreshAsync(ct);
        var atA = (await catalog.FindByIdAsync("acme", ct))!;
        LicenseChecker.CheckIssuer(A, Settings(catalog, atA));

        listed[0] = At("acme", B, "2");
        await catalog.RefreshAsync(ct);
        var atB = (await catalog.FindByIdAsync("acme", ct))!;
        time.Advance(Pause / 2);
        listed[0] = At("acme", C, "3");
        await catalog.RefreshAsync(ct);

        Assert.Equal(A, LicenseChecker.CheckIssuer(A, Settings(catalog, atA)));
        Assert.Equal(B, LicenseChecker.CheckIssuer(B, Settings(catalog, atB)));

        time.Advance(Pause / 2);
        await catalog.RefreshAsync(ct);
        Assert.Throws<LicenseViolationException>(() => LicenseChecker.CheckIssuer(A, Settings(catalog, atA)));
        Assert.Equal(B, LicenseChecker.CheckIssuer(B, Settings(catalog, atB)));

        time.Advance(Pause / 2);
        await catalog.RefreshAsync(ct);
        Assert.Throws<LicenseViolationException>(() => LicenseChecker.CheckIssuer(B, Settings(catalog, atB)));
    }

    [Fact]
    public async Task The_address_served_now_counts_as_the_tenant_while_a_reading_closes_another_tenant()
    {
        var ct = TestContext.Current.CancellationToken;
        var listed = new List<StoredTenant> { At("acme", A, "1"), At("globex", G, "1") };
        var time = new FakeTimeProvider();
        var seen = new List<bool>();
        StoreTenantCatalog catalog = null!;
        TenantDefinition atA = null!;
        catalog = Catalog(listed, time, new CheckingClosing(
            () =>
            {
                try
                {
                    LicenseChecker.CheckIssuer(A, Settings(catalog, atA));
                    return true;
                }
                catch (LicenseViolationException)
                {
                    return false;
                }
            },
            seen));
        await catalog.RefreshAsync(ct);
        atA = (await catalog.FindByIdAsync("acme", ct))!;
        LicenseChecker.CheckIssuer(A, Settings(catalog, atA));

        listed.RemoveAt(1);
        await catalog.RefreshAsync(ct);
        time.Advance(Pause);
        await catalog.RefreshAsync(ct);

        Assert.Equal([true], seen);
    }

    [Fact]
    public async Task A_late_request_of_a_released_creation_beside_its_successor_counts_as_the_tenant()
    {
        var ct = TestContext.Current.CancellationToken;
        var listed = new List<StoredTenant> { At("acme", A, "1") };
        var time = new FakeTimeProvider();
        var catalog = Catalog(listed, time);
        await catalog.RefreshAsync(ct);
        var g1 = (await catalog.FindByIdAsync("acme", ct))!;

        listed[0] = At("acme", A, "2", "g2");
        await catalog.RefreshAsync(ct);
        var g2 = (await catalog.FindByIdAsync("acme", ct))!;
        LicenseChecker.CheckIssuer(A, Settings(catalog, g2));
        time.Advance(Pause);
        await catalog.RefreshAsync(ct);

        Assert.Equal(A, LicenseChecker.CheckIssuer(A, Settings(catalog, g1)));
    }

    private static StoredTenant At(string id, string issuer, string version, string generation = "g1")
        => new(new TenantDefinition { Id = id, Issuer = new Uri(issuer), Generation = generation }, version);

    private static StoreTenantCatalog Catalog(
        List<StoredTenant> listed,
        FakeTimeProvider time,
        params ITenantClosing[] closings)
    {
        var store = new Mock<ITenantStore>();
        store.Setup(s => s.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => listed.ToArray());
        var opening = new Mock<ITenantOpening>();
        opening
            .Setup(o => o.OpenAsync(It.IsAny<IReadOnlyCollection<TenantDefinition>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Dictionary<string, Exception>());
        return new StoreTenantCatalog(
            NullLogger<StoreTenantCatalog>.Instance,
            store.Object,
            [new TenantDefinitionsCheck()],
            [opening.Object],
            closings,
            Options.Create(new OidcOptions()),
            time);
    }

    private static TenantIssuerSettings Settings(StoreTenantCatalog catalog, TenantDefinition tenant)
    {
        var served = new TenantContext { Tenant = tenant };
        return new TenantIssuerSettings(
            Mock.Of<ITenantAccessor>(accessor => accessor.Current == served),
            Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == new OidcOptions()),
            catalog);
    }

    private static TenantDefinition Entered(TenantDefinition served, string issuer)
        => new() { Id = served.Id, Issuer = new Uri(issuer), Generation = served.Generation };

    /// <summary>A closing that takes a while, moving the clock on as it does.</summary>
    private sealed class SlowClosing(FakeTimeProvider time, TimeSpan takes) : ITenantClosing
    {
        public Task<IReadOnlyDictionary<TenantDefinition, Exception>> CloseAsync(
            IReadOnlyCollection<TenantDefinition> tenants,
            CancellationToken cancellationToken)
        {
            time.Advance(takes);
            return Task.FromResult<IReadOnlyDictionary<TenantDefinition, Exception>>(
                new Dictionary<TenantDefinition, Exception>());
        }
    }

    /// <summary>A closing that records what a request answered while a reading was closing a tenant.</summary>
    private sealed class CheckingClosing(Func<bool> check, List<bool> seen) : ITenantClosing
    {
        public Task<IReadOnlyDictionary<TenantDefinition, Exception>> CloseAsync(
            IReadOnlyCollection<TenantDefinition> tenants,
            CancellationToken cancellationToken)
        {
            seen.Add(check());
            return Task.FromResult<IReadOnlyDictionary<TenantDefinition, Exception>>(
                new Dictionary<TenantDefinition, Exception>());
        }
    }
}
