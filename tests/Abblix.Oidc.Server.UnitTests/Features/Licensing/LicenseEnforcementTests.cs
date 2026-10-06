// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.Features.Telemetry;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// Exercises the enforcement decisions by calling <see cref="LicenseChecker"/> itself.
/// </summary>
/// <remarks>
/// These replace an earlier set that never called the product. Those built their own dictionary of seen
/// issuers, re-computed the comparison the checker makes, and asserted the re-computation
/// (<c>var shouldThrow = license.IssuerLimit &lt; knownIssuers.Count; Assert.True(shouldThrow)</c>). That form
/// asserts arithmetic: it stays green if the enforcement is deleted outright, while reading as coverage and so
/// discouraging anyone from looking again.
///
/// Each test starts from a known point and the class does not run beside others, because the checker keeps what
/// it has seen in process-wide statics. Without that, a limit is reachable only by whichever test happens to
/// run first.
/// </remarks>
[Collection(nameof(LicenseEnforcementTests))]
[CollectionDefinition(nameof(LicenseEnforcementTests), DisableParallelization = true)]
public sealed class LicenseEnforcementTests : IDisposable
{
    private const string UnlicensedIssuer = "https://second-issuer.example.com";

    public LicenseEnforcementTests() => TestLicense.ResetChecker();

    /// <summary>Leaves the assembly's license in place for everything that runs afterwards.</summary>
    public void Dispose() => TestLicense.ResetChecker();

    [Fact]
    public void The_issuer_the_licence_names_is_accepted()
    {
        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Settings));
    }

    [Fact]
    public void An_issuer_the_licence_does_not_name_is_refused()
    {
        // The whitelist is what ties a license to the deployment it was issued for. Without it, a license file
        // works wherever it is copied.
        var refusal = Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));
        Assert.Equal(LicenseRefusalReasons.IssuerNotAllowed, refusal.Reason);
    }

    [Fact]
    public async Task A_refusal_inside_an_endpoint_is_counted_by_its_reason()
    {
        // The count is taken by the endpoint serving the request, from the refusal the checker throws, so the
        // checker itself reads nothing a host registers
        await using var services = new ServiceCollection().AddMetrics().BuildServiceProvider();
        var meters = services.GetRequiredService<IMeterFactory>();
        using var measured = new MeasurementRecorder(meters);

        await Assert.ThrowsAsync<LicenseViolationException>(() => EndpointObservation.RunAsync(
            TelemetryEndpoints.UserInfo,
            new OidcInstruments(NullLoggerFactory.Instance, meters),
            null,
            () => Task.FromResult(LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings)),
            EndpointObservation.NoError));

        var refusal = Assert.Single(measured.Of(OidcMetrics.LicenseRefusals));
        Assert.Equal(LicenseRefusalReasons.IssuerNotAllowed, refusal[TelemetryTags.LicenseRefusalReason]);
    }

    [Fact]
    public void An_issuer_the_licence_does_not_name_is_refused_every_time()
    {
        // Refused on every call, not only the first. A rule that stops applying once it has been reported is
        // not a rule: the caller only has to ask again, and a retry policy does that without anyone deciding
        // to. Asserted separately from the single-call case because a single call cannot tell the two apart.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            Assert.Throws<LicenseViolationException>(
                () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));
        }
    }

    [Fact]
    public void An_issuer_beyond_the_licensed_count_is_refused_every_time()
    {
        // A license that caps the number of issuers without naming them, which is the only arrangement under
        // which the count is ever consulted: a license that names its issuers refuses an unknown one on the
        // name, before anything is counted. Written this way after the first attempt, which reused the
        // assembly's license, turned out to exercise the whitelist while claiming to test the count.
        ArrangeLicenceThatCountsIssuers();

        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Settings));

        // Every call, not only the first. A limit that stops applying once it has been reported is not a
        // limit: the caller only has to ask again, and a retry policy does that without anyone deciding to.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var refusal = Assert.Throws<LicenseViolationException>(
                () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));
            Assert.Equal(LicenseRefusalReasons.IssuerLimit, refusal.Reason);
        }
    }

    [Fact]
    public void A_client_is_accepted_while_the_licence_sets_no_client_limit()
    {
        // The assembly license carries no client_limit, so clients are unbounded. Worth pinning: were a later
        // license to introduce one, the whole suite would start tripping it, and the failure would look like
        // anything except a change of license terms.
        var client = new ClientInfo("some-client");

        Assert.True(Issues(client, SingleIssuer.Settings));
    }

    [Fact]
    public void An_installation_running_before_a_licence_is_supplied_serves_one_issuer_and_refuses_the_second()
    {
        // The one limit the free tier has. Its sibling
        // An_installation_running_before_a_licence_is_supplied_still_serves_every_client pins the client half
        // of the same fallback, and that asymmetry is how this went missing: every other test reaching CheckIssuer
        // either runs under the assembly license, and so is refused on the whitelist before anything is counted, or
        // supplies a license of its own carrying the limit. None of them asks the fallback what it allows, so the
        // constant could be deleted outright with the whole suite still green - measured, not assumed. A deployment
        // of one issuer may take its issuer from the address of each request, so there the address is what counts.
        ArrangeInstallationWithNoLicence();

        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Settings));

        // Every time, not only the first: a limit that stops applying once reported is not a limit.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            Assert.Throws<LicenseViolationException>(
                () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));
        }
    }

    [Fact]
    public void The_refusal_past_the_issuer_limit_is_recorded()
    {
        // The refusal is covered by An_issuer_beyond_the_licensed_count_is_refused_every_time; this covers
        // the record of it, which an operator's alerting is built on. It went untested for a mechanical reason worth
        // stating: the throttle window is process-wide and fifteen minutes long, so whichever test reached the limit
        // first consumed the only record any test could observe, and every later one found the decision taken in
        // silence.
        //
        // On a license of its own rather than on the unlicensed fallback, so that this test and the fallback
        // test fail for different reasons: removing the fallback's limit must not be able to take this one
        // down with it, or the two stop measuring two things.
        ArrangeLicenceThatCountsIssuers();
        TestLicense.ClearLogThrottle();

        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Settings));
            Assert.Throws<LicenseViolationException>(
                () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        var record = Assert.Single(records.Entries);
        Assert.Equal(LogEvents.Licensing.LicenseChecker.IssuerLimitExceeded, record.EventId.Id);
        Assert.Equal(LogLevel.Error, record.Level);

        // The message carries what an operator needs to act: which issuers were counted against the limit.
        Assert.Contains(UnlicensedIssuer, record.Message, StringComparison.Ordinal);
        Assert.Contains(TestLicense.Issuer, record.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Puts the checker where an installation is before any license has been supplied.
    /// </summary>
    /// <remarks>
    /// The assembly installs its license before the first test runs, so reaching the state a deployment
    /// starts in means removing it. That state is the subject of
    /// <see cref="An_installation_running_before_a_licence_is_supplied_serves_one_issuer_and_refuses_the_second"/>
    /// and <see cref="An_installation_running_before_a_licence_is_supplied_still_serves_every_client"/> rather
    /// than a convenience for them: it is the only state in which the fallback is ever consulted.
    /// </remarks>
    private static void ArrangeInstallationWithNoLicence() => TestLicense.ClearChecker();

    /// <summary>
    /// Puts the checker on a license for one issuer that names none, so the second issuer is the one refused.
    /// </summary>
    private static void ArrangeLicenceThatCountsIssuers() => TestLicense.InstallWithIssuerLimit(1);

    /// <summary>
    /// A tenant that would take the server past the license's issuer limit is refused when the manager of the
    /// tenants is asked to create it, so the tenants already served keep working instead of all being refused on
    /// their next request; under a limit with room for it, the same tenant is created.
    /// </summary>
    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    public async Task A_tenant_beyond_the_issuer_limit_is_refused_when_created(int issuerLimit, bool created)
    {
        var ct = TestContext.Current.CancellationToken;
        TestLicense.InstallWithIssuerLimit(issuerLimit);
        var store = new WritableTenantStore();
        await store.AddAsync(new TenantDefinition { Id = "acme", Issuer = "https://acme.example.com" }, ct);
        var catalog = Catalog(store);
        var manager = new TenantManager(
            NullLogger<TenantManager>.Instance, store, [new TenantDefinitionsCheck()], catalog, store);

        var result = await manager.CreateAsync(
            new TenantDefinition { Id = "globex", Issuer = "https://globex.example.com" }, ct);

        Assert.Equal(created, result.TryGetSuccess(out _));
        Assert.Equal(created ? 2 : 1, store.Tenants.Count);
        if (!created)
        {
            Assert.True(result.TryGetFailure(out var refusal));
            Assert.Equal(TenantChangeRefusalReason.BeyondLicense, refusal.Reason);
        }
    }

    [Fact]
    public void An_installation_running_before_a_licence_is_supplied_still_serves_every_client()
    {
        // The terms meter company size and production issuers, never client applications, so the fallback an
        // installation runs on before any license is supplied must not count clients either. Written against
        // the fallback itself - no license is added after the clear - because that is the only state in which
        // it is ever consulted, and a license carrying no client limit would pass whatever the fallback said.
        ArrangeInstallationWithNoLicence();

        for (var index = 0; index < 20; index++)
        {
            var client = new ClientInfo($"unlicensed-client-{index}");
            Assert.True(Issues(client, SingleIssuer.Settings));
        }
    }

    [Fact]
    public void A_client_far_beyond_the_licensed_count_is_turned_away()
    {
        // The client limit is not refused at the limit but at a margin above it, so an operator who has grown
        // slightly past their terms keeps serving while being told. Past the margin the client is turned away
        // outright - the checker answers null and the caller treats it as an unknown client.
        TestLicense.ClearChecker();
        LicenseChecker.AddLicense(new License
        {
            ClientLimit = 2,
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });

        // Within the margin: recorded and served, which is the tolerance the margin exists to give.
        for (var index = 0; index < 3; index++)
        {
            var tolerated = new ClientInfo($"client-{index}");
            Assert.True(Issues(tolerated, SingleIssuer.Settings));
        }

        // Past it: a client never seen before is refused, every time it asks.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            Assert.False(Issues(new ClientInfo("one-client-too-many"), SingleIssuer.Settings));
        }
    }

    [Fact]
    public void A_tenant_gone_for_good_no_longer_counts_toward_the_issuer_limit()
    {
        // The license meters the issuers served, not every issuer the process ever saw: a tenant released from the
        // store gives its place to the next, so a deployment whose tenants come and go stays within its terms
        ArrangeInstallationWithNoLicence();
        using var released = new CancellationTokenSource();
        var gone = Creation("acme", released.Token);

        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, gone));
        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));

        released.Cancel();
        Assert.Equal(UnlicensedIssuer, LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));
    }

    [Fact]
    public void The_clients_of_a_tenant_gone_for_good_no_longer_count_toward_the_client_limit()
    {
        TestLicense.ClearChecker();
        LicenseChecker.AddLicense(new License
        {
            ClientLimit = 2,
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });
        using var released = new CancellationTokenSource();
        var gone = Creation("acme", released.Token);
        var globex = Creation("globex", CancellationToken.None);

        // Past the margin with the clients of a tenant about to go
        for (var index = 0; index < 3; index++)
        {
            var client = new ClientInfo($"client-{index}");
            Assert.True(Issues(client, gone));
        }

        Assert.False(Issues(new ClientInfo("newcomer"), globex));

        released.Cancel();
        var newcomer = new ClientInfo("newcomer");
        Assert.True(Issues(newcomer, globex));
    }

    [Fact]
    public void A_tenant_created_again_keeps_its_place_when_its_earlier_creation_is_released()
    {
        // A tenant removed and created again under its id is served by the new creation while the earlier one
        // still awaits release; that release must not take the place the new creation holds
        ArrangeInstallationWithNoLicence();
        using var earlier = new CancellationTokenSource();
        using var later = new CancellationTokenSource();

        LicenseChecker.CheckIssuer(TestLicense.Issuer, Creation("acme", earlier.Token));
        LicenseChecker.CheckIssuer(TestLicense.Issuer, Creation("acme", later.Token));
        earlier.Cancel();

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));
    }

    [Fact]
    public void A_tenant_created_again_keeps_its_place_while_requests_of_the_earlier_creation_finish()
    {
        // Requests of both creations are served during the pause: whichever counted last, the release of the
        // earlier creation leaves the place the later one holds
        ArrangeInstallationWithNoLicence();
        using var earlier = new CancellationTokenSource();
        using var later = new CancellationTokenSource();

        LicenseChecker.CheckIssuer(TestLicense.Issuer, Creation("acme", earlier.Token));
        LicenseChecker.CheckIssuer(TestLicense.Issuer, Creation("acme", later.Token));
        LicenseChecker.CheckIssuer(TestLicense.Issuer, Creation("acme", earlier.Token));
        earlier.Cancel();

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));
    }

    [Fact]
    public void A_late_request_of_a_released_creation_neither_counts_nor_frees_the_place_of_the_live_one()
    {
        // A request still holding a creation released already carries a canceled token while the catalog remembers
        // the release: it counts for nothing, and the creation serving the tenant now keeps its place
        ArrangeInstallationWithNoLicence();
        using var later = new CancellationTokenSource();
        LicenseChecker.CheckIssuer(TestLicense.Issuer, Creation("acme", later.Token));

        LicenseChecker.CheckIssuer(TestLicense.Issuer, Creation("acme", new CancellationToken(true)));

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));

        // Nor does it hold the place once the live creation goes
        later.Cancel();
        Assert.Equal(UnlicensedIssuer, LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));
    }

    [Fact]
    public void A_tenant_moved_to_another_address_keeps_one_place()
    {
        // The issuers of a deployment of tenants are counted by tenant, so the address a tenant left does not stay
        // on the count beside the one it serves now
        ArrangeInstallationWithNoLicence();
        var acme = Creation("acme", CancellationToken.None);

        LicenseChecker.CheckIssuer(TestLicense.Issuer, acme);

        Assert.Equal(UnlicensedIssuer, LicenseChecker.CheckIssuer(UnlicensedIssuer, acme));
    }

    [Fact]
    public async Task A_tenant_dropped_from_the_store_frees_its_place_once_the_catalog_releases_it()
    {
        // Through the server's own catalog: the place stays taken through the pause after the store drops the
        // tenant, as a request may still be serving it, and is freed once the catalog releases it
        ArrangeInstallationWithNoLicence();
        var ct = TestContext.Current.CancellationToken;
        var listed = new List<StoredTenant>
        {
            new(new TenantDefinition { Id = "acme", Issuer = TestLicense.Issuer, Generation = "g1" }, "1"),
        };
        var store = new Mock<ITenantStore>();
        store.Setup(s => s.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => listed.ToArray());
        var time = new FakeTimeProvider();
        var catalog = Catalog(store.Object, time);
        await catalog.RefreshAsync(ct);
        var acme = Settings(catalog, (await catalog.FindByIdAsync("acme", ct))!);
        LicenseChecker.CheckIssuer(TestLicense.Issuer, acme);

        listed.Clear();
        await catalog.RefreshAsync(ct);
        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));

        time.Advance(new MultiTenancyOptions().RefreshEvery);
        await catalog.RefreshAsync(ct);
        Assert.Equal(UnlicensedIssuer, LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));
    }

    [Fact]
    public async Task A_client_removed_through_registration_frees_its_place()
    {
        // A client its registrant deleted is no longer served, so the next client takes its place
        ArrangeClientLimitOfTwo();
        var removed = new RegisteredClient(new ClientInfo("client-0"), "jti");
        CountPastTheMargin(SingleIssuer.Settings, removed.ClientInfo);

        await RemoveThroughRegistrationAsync(removed, SingleIssuer.Settings);

        AssertOnePlaceFree(SingleIssuer.Settings);
    }

    [Fact]
    public async Task A_client_removed_through_registration_frees_the_place_it_held_at_its_tenant()
    {
        ArrangeClientLimitOfTwo();
        var ct = TestContext.Current.CancellationToken;
        var store = new Mock<ITenantStore>();
        store.Setup(s => s.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync([Acme("1")]);
        var catalog = Catalog(store.Object);
        await catalog.RefreshAsync(ct);
        var acme = Settings(catalog, (await catalog.FindByIdAsync("acme", ct))!);
        var removed = new RegisteredClient(new ClientInfo("client-0"), "jti");
        CountPastTheMargin(acme, removed.ClientInfo);

        await RemoveThroughRegistrationAsync(removed, acme);

        AssertOnePlaceFree(acme);
    }

    [Fact]
    public async Task A_client_removed_at_one_tenant_keeps_its_place_at_another()
    {
        // Two tenants count a client under one id, each its own: deleting it at one leaves the other's counted
        ArrangeClientLimitOfTwo();
        var acme = Creation("acme", CancellationToken.None);
        var globex = Creation("globex", CancellationToken.None);
        var removed = new RegisteredClient(new ClientInfo("client-0"), "jti");
        _ = Issues(removed.ClientInfo, acme);
        _ = Issues(new ClientInfo("client-0"), globex);
        _ = Issues(new ClientInfo("client-1"), globex);
        Assert.False(Issues(new ClientInfo("newcomer"), globex));

        await RemoveThroughRegistrationAsync(removed, acme);

        AssertOnePlaceFree(globex);
    }

    [Fact]
    public async Task A_client_a_tenant_no_longer_configures_frees_its_place_once_the_change_is_served()
    {
        // A change of the tenant dropping one of its configured clients takes that client off the count when the
        // catalog serves the change
        ArrangeClientLimitOfTwo();
        var ct = TestContext.Current.CancellationToken;
        var listed = new[] { Acme("1", "client-0", "client-1", "client-2") };
        var store = new Mock<ITenantStore>();
        store.Setup(s => s.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => listed);
        var catalog = Catalog(store.Object);
        await catalog.RefreshAsync(ct);
        var acme = Settings(catalog, (await catalog.FindByIdAsync("acme", ct))!);
        foreach (var client in listed[0].Tenant.Clients)
            _ = Issues(client, acme);
        Assert.False(Issues(new ClientInfo("newcomer"), acme));

        listed = [Acme("2", "client-1", "client-2")];
        await catalog.RefreshAsync(ct);

        AssertOnePlaceFree(acme);
    }

    [Fact]
    public async Task A_client_a_reload_of_the_settings_drops_frees_its_place_once_the_reloaded_settings_are_served()
    {
        // A server without tenants serving its clients from the reloadable store takes a client the reloaded
        // settings no longer configure off the count when it first serves them
        ArrangeClientLimitOfTwo();
        var current = new OidcOptions { Clients = [new("client-0"), new("client-1"), new("client-2")] };
        var monitor = new Mock<IOptionsMonitor<OidcOptions>>();
        monitor.SetupGet(options => options.CurrentValue).Returns(() => current);
        var settings = new OptionsIssuerSettings(monitor.Object);
        var clients = new ReloadableClientInfoStorage(
            NullLogger<ReloadableClientInfoStorage>.Instance,
            settings,
            new SingleIssuerLocal<Dictionary<string, ClientInfo>>(),
            new IssuerClientRegistrations(new SingleIssuerLocal<ConcurrentDictionary<string, RegisteredClient>>()));
        foreach (var client in current.Clients)
            _ = Issues((await clients.TryFindClientAsync(client.ClientId))!, settings);
        Assert.False(Issues(new ClientInfo("newcomer"), settings));

        current = new OidcOptions { Clients = [new("client-1"), new("client-2")] };
        await clients.TryFindClientAsync("client-1");

        AssertOnePlaceFree(settings);
    }

    /// <summary>
    /// Counts <paramref name="first"/> and two more clients of <paramref name="issuer"/>, past the margin over a
    /// limit of two, so a newcomer is refused.
    /// </summary>
    private static void CountPastTheMargin(IIssuerSettings issuer, ClientInfo first)
    {
        _ = Issues(first, issuer);
        for (var index = 1; index < 3; index++)
            _ = Issues(new ClientInfo($"client-{index}"), issuer);

        Assert.False(Issues(new ClientInfo("newcomer"), issuer));
    }

    /// <summary>
    /// Exactly one place is free: a newcomer is served, and the one after it is refused, so the clients still served
    /// kept theirs.
    /// </summary>
    private static void AssertOnePlaceFree(IIssuerSettings issuer)
    {
        var newcomer = new ClientInfo("newcomer");
        Assert.True(Issues(newcomer, issuer));
        Assert.False(Issues(new ClientInfo("newcomer-2"), issuer));
    }

    /// <summary>
    /// Whether a token can be issued to <paramref name="client"/> under <paramref name="issuer"/>: the check that counts
    /// the client, run where a token names its issuer.
    /// </summary>
    private static bool Issues(ClientInfo client, IIssuerSettings settings, string issuer = TestLicense.Issuer)
    {
        try
        {
            LicenseChecker.CheckLicense(issuer, settings, client.ClientId);
            return true;
        }
        catch (LicenseViolationException)
        {
            return false;
        }
    }

    private static async Task RemoveThroughRegistrationAsync(RegisteredClient removed, IIssuerSettings issuer)
    {
        var clients = new Mock<IClientInfoManager>();
        clients.Setup(manager => manager.TryRemoveClientAsync(removed)).ReturnsAsync(true);
        var result = await new RemoveClientRequestProcessor(clients.Object, TimeProvider.System, issuer)
            .ProcessAsync(new ValidClientRequest(new ClientRequest(), removed));
        Assert.True(result.TryGetSuccess(out _));
    }

    private static void ArrangeClientLimitOfTwo()
    {
        TestLicense.ClearChecker();
        LicenseChecker.AddLicense(new License
        {
            ClientLimit = 2,
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });
    }

    private static StoredTenant Acme(string version, params string[] clientIds) => new(
        new TenantDefinition
        {
            Id = "acme",
            Issuer = TestLicense.Issuer,
            Generation = "g1",
            Clients = clientIds.Select(clientId => new ClientInfo(clientId)).ToArray(),
        },
        version);

    private static StoreTenantCatalog Catalog(ITenantStore store, TimeProvider? time = null)
    {
        var opening = new Mock<ITenantOpening>();
        opening
            .Setup(o => o.OpenAsync(It.IsAny<IReadOnlyCollection<TenantDefinition>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Dictionary<string, Exception>());
        return new StoreTenantCatalog(
            NullLogger<StoreTenantCatalog>.Instance,
            store,
            [new TenantDefinitionsCheck()],
            [opening.Object],
            [],
            Options.Create(new MultiTenancyOptions()),
            time ?? new FakeTimeProvider());
    }

    private static TenantIssuerSettings Settings(StoreTenantCatalog catalog, TenantDefinition tenant)
    {
        var served = new TenantContext { Tenant = tenant };
        return new TenantIssuerSettings(
            Mock.Of<ITenantAccessor>(accessor => accessor.Current == served),
            Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == new OidcOptions()),
            catalog);
    }

    /// <summary>
    /// The settings of a tenant's creation, released when <paramref name="released"/> is canceled.
    /// </summary>
    private static IIssuerSettings Creation(string tenantId, CancellationToken released)
        => new LicensedTenantSettings(tenantId, released);

    /// <summary>
    /// Settings a host registers do not tell the license an issuer is gone: one answering it is released still
    /// takes its place, so the second issuer past a limit of one is refused.
    /// </summary>
    [Fact]
    public void Settings_of_the_hosts_own_saying_released_still_count()
    {
        ArrangeLicenceThatCountsIssuers();
        var released = Mock.Of<IIssuerSettings>(settings =>
            settings.Id == string.Empty && settings.Released == new CancellationToken(true));

        LicenseChecker.CheckIssuer("https://acme.example.com", released);

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer("https://globex.example.com", released));
    }

    /// <summary>
    /// Settings a host registers do not tell the license which tenant an issuer is: two issuers answering one id
    /// take two places.
    /// </summary>
    [Fact]
    public void Settings_of_the_hosts_own_naming_one_id_count_each_issuer()
    {
        ArrangeLicenceThatCountsIssuers();
        var sameId = Mock.Of<IIssuerSettings>(settings => settings.Id == "acme");

        LicenseChecker.CheckIssuer("https://acme.example.com", sameId);

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer("https://globex.example.com", sameId));
    }

    /// <summary>
    /// Settings a host registers do not tell the license which tenant a client belongs to: a client id two issuers
    /// serve takes a place under each issuer the tokens name.
    /// </summary>
    [Fact]
    public void Clients_of_settings_of_the_hosts_own_are_counted_with_the_issuer_of_the_token()
    {
        ArrangeClientLimitOfTwo();
        var sameId = Mock.Of<IIssuerSettings>(settings => settings.Id == "acme");

        _ = Issues(new ClientInfo("web"), sameId, "https://acme.example.com");
        _ = Issues(new ClientInfo("web"), sameId, "https://globex.example.com");
        _ = Issues(new ClientInfo("mobile"), sameId, "https://acme.example.com");

        Assert.False(Issues(new ClientInfo("mobile"), sameId, "https://globex.example.com"));
    }

    /// <summary>
    /// Settings of the host's own saying they are released do not take their clients off the count.
    /// </summary>
    [Fact]
    public void Clients_of_settings_of_the_hosts_own_saying_released_still_count()
    {
        ArrangeClientLimitOfTwo();
        var released = Mock.Of<IIssuerSettings>(settings =>
            settings.Id == string.Empty && settings.Released == new CancellationToken(true));

        CountPastTheMargin(released, new ClientInfo("client-0"));
    }

    /// <summary>
    /// A client removed through registration under settings of the host's own stays counted: the license cannot tell
    /// which of the issuers those settings serve it was counted with, even when their id spells the issuer itself.
    /// </summary>
    [Fact]
    public async Task A_client_removed_under_settings_of_the_hosts_own_keeps_its_place()
    {
        ArrangeClientLimitOfTwo();
        var hosts = Mock.Of<IIssuerSettings>(settings => settings.Id == TestLicense.Issuer);
        var removed = new RegisteredClient(new ClientInfo("client-0"), "jti");
        CountPastTheMargin(hosts, removed.ClientInfo);

        await RemoveThroughRegistrationAsync(removed, hosts);

        Assert.False(Issues(new ClientInfo("newcomer"), hosts));
    }

    /// <summary>
    /// The server's own settings vouch for a tenant only as its own catalog serves it: one a catalog of the host's own
    /// resolved is counted by the issuer its tokens name, so two issuers answered under one tenant id take two places.
    /// </summary>
    [Fact]
    public void A_tenant_a_catalog_of_the_hosts_own_resolved_is_counted_by_its_issuer()
    {
        ArrangeLicenceThatCountsIssuers();
        var served = new TenantContext { Tenant = new TenantDefinition { Id = "acme", Issuer = "https://acme.example.com" } };
        var settings = new TenantIssuerSettings(
            Mock.Of<ITenantAccessor>(accessor => accessor.Current == served),
            Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == new OidcOptions()),
            Mock.Of<ITenantCatalog>());

        LicenseChecker.CheckIssuer("https://acme.example.com", settings);

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer("https://globex.example.com", settings));
    }

    [Fact]
    public void A_client_already_known_is_still_served_once_the_margin_is_passed()
    {
        // The refusal applies to clients the deployment has not served before. One already in use keeps
        // working, so exceeding the terms degrades the ability to add clients rather than breaking the ones
        // already relying on it.
        TestLicense.ClearChecker();
        LicenseChecker.AddLicense(new License
        {
            ClientLimit = 2,
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });

        for (var index = 0; index < 3; index++)
        {
            _ = Issues(new ClientInfo($"established-{index}"), SingleIssuer.Settings);
        }

        Assert.False(Issues(new ClientInfo("newcomer"), SingleIssuer.Settings));

        var established = new ClientInfo("established-0");
        Assert.True(Issues(established, SingleIssuer.Settings));
    }

    [Fact]
    public void A_client_id_two_tenants_register_counts_once_for_each()
    {
        // Two tenants may each register a client under one id, and each is a client the deployment serves. Counted
        // by the bare id, the second tenant's clients would ride on the first's and never reach the limit.
        TestLicense.ClearChecker();
        LicenseChecker.AddLicense(new License
        {
            ClientLimit = 2,
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });
        var acme = Creation("acme", CancellationToken.None);
        var globex = Creation("globex", CancellationToken.None);

        _ = Issues(new ClientInfo("web"), acme);
        _ = Issues(new ClientInfo("web"), globex);
        _ = Issues(new ClientInfo("mobile"), acme);

        Assert.False(Issues(new ClientInfo("mobile"), globex));
    }

    [Fact]
    public void A_refusal_is_recorded_for_each_tenant_refusing_a_client_of_one_id()
    {
        // The record of a refusal is throttled per client, so a client is named with its tenant there too: counted
        // by the bare id, the second tenant's refusal would be taken in silence for the first one's record.
        TestLicense.ClearChecker();
        TestLicense.ClearLogThrottle();
        LicenseChecker.AddLicense(new License
        {
            ClientLimit = 1,
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });
        var acme = Creation("acme", CancellationToken.None);
        var globex = Creation("globex", CancellationToken.None);
        _ = Issues(new ClientInfo("first"), acme);
        _ = Issues(new ClientInfo("second"), acme);

        var records = new RecordingLoggerFactory();
        LicenseLogger.Instance.Init(records);
        try
        {
            Assert.False(Issues(new ClientInfo("web"), acme));
            Assert.False(Issues(new ClientInfo("web"), globex));
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }

        var refusals = records.Entries
            .Where(record => record.EventId.Id == LogEvents.Licensing.LicenseChecker.ClientLimitExceededByMargin)
            .Select(record => record.Message)
            .ToArray();
        Assert.Equal(2, refusals.Length);
        Assert.Contains(refusals, message => message.Contains("acme/web", StringComparison.Ordinal));
        Assert.Contains(refusals, message => message.Contains("globex/web", StringComparison.Ordinal));
    }

    [Fact]
    public void A_reporting_failure_does_not_change_the_decision()
    {
        // Enforcement must not depend on reporting succeeding. The logger written through here is a
        // process-wide singleton whose underlying logger is rebound by every host that starts and released by
        // none, so it can be left pointing at a provider that is gone - which throws on write. Were that
        // allowed to escape, the license decision would be replaced by an unrelated exception from the logging
        // stack, and the request would fail for a reason having nothing to do with the license.
        LicenseLogger.Instance.Init(new ThrowingLoggerFactory());
        try
        {
            Assert.Throws<LicenseViolationException>(
                () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Settings));
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }
    }

    /// <summary>A factory whose loggers fail on write, standing in for one whose provider has been disposed.</summary>
    private sealed class ThrowingLoggerFactory : ILoggerFactory
    {
        public ILogger CreateLogger(string categoryName) => new ThrowingLogger();

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public void Dispose()
        {
        }

        private sealed class ThrowingLogger : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
                => throw new ObjectDisposedException("the provider this logger came from is gone");
        }
    }
}
