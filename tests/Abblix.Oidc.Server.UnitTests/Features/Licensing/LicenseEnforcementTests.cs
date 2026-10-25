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
    private const string ThirdIssuer = "https://third-issuer.example.com";
    private const string GlobexIssuer = "https://globex.example.com";

    public LicenseEnforcementTests() => TestLicense.ResetChecker();

    /// <summary>Leaves the assembly's license in place for everything that runs afterwards.</summary>
    public void Dispose() => TestLicense.ResetChecker();

    [Fact]
    public void The_issuer_the_licence_names_is_accepted()
    {
        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
    }

    [Fact]
    public void An_issuer_the_licence_does_not_name_is_refused()
    {
        // The whitelist is what ties a license to the deployment it was issued for. Without it, a license file
        // works wherever it is copied.
        var refusal = Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
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
            NoTenant.Accessor,
            () => Task.FromResult(LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog)),
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
                () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
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

        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));

        // Every call, not only the first. A limit that stops applying once it has been reported is not a
        // limit: the caller only has to ask again, and a retry policy does that without anyone deciding to.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var refusal = Assert.Throws<LicenseViolationException>(
                () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
            Assert.Equal(LicenseRefusalReasons.IssuerLimit, refusal.Reason);
        }
    }

    /// <summary>
    /// The issuer beyond the count is the one refused: an issuer served within the limit keeps being served after a
    /// further one has asked, so one extra issuer cannot stop the whole deployment.
    /// </summary>
    [Fact]
    public void An_issuer_within_the_licensed_count_is_still_served_after_one_beyond_it_asked()
    {
        ArrangeLicenceThatCountsIssuers();
        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));

        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
    }

    [Fact]
    public void A_client_is_accepted_while_the_licence_sets_no_client_limit()
    {
        // The assembly license carries no client_limit, so clients are unbounded. Worth pinning: were a later
        // license to introduce one, the whole suite would start tripping it, and the failure would look like
        // anything except a change of license terms.
        var client = new ClientInfo("some-client");

        Assert.True(Issues(client, AtTheHost));
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

        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));

        // Every time, not only the first: a limit that stops applying once reported is not a limit.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            Assert.Throws<LicenseViolationException>(
                () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
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
            Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
            Assert.Throws<LicenseViolationException>(
                () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
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
        await store.AddAsync(new TenantDefinition { Id = "acme", Issuer = new Uri("https://acme.example.com") }, ct);
        var catalog = Catalog(store);
        var manager = new TenantManager(
            NullLogger<TenantManager>.Instance, store, [new TenantDefinitionsCheck()], catalog, Options.Create(new OidcOptions()), store);

        var result = await manager.CreateAsync(
            new TenantDefinition { Id = "globex", Issuer = new Uri("https://globex.example.com") }, ct);

        Assert.Equal(created, result.TryGetSuccess(out _));
        Assert.Equal(created ? 2 : 1, store.Tenants.Count);
        if (!created)
        {
            Assert.True(result.TryGetFailure(out var refusal));
            Assert.Equal(TenantChangeRefusalReason.BeyondLicense, refusal.Reason);
        }
    }

    /// <summary>
    /// A tenant whose issuer the license does not name would be refused on every request, so the manager of the
    /// tenants refuses to create it, or to move a tenant to such an issuer.
    /// </summary>
    [Fact]
    public async Task A_tenant_whose_issuer_the_license_does_not_name_is_neither_created_nor_moved_there()
    {
        var ct = TestContext.Current.CancellationToken;
        TestLicense.ClearChecker();
        LicenseChecker.AddLicense(new License
        {
            ValidIssuers = ["https://acme.example.com", "https://globex.example.com"],
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });
        var store = new WritableTenantStore();
        await store.AddAsync(new TenantDefinition { Id = "acme", Issuer = new Uri("https://acme.example.com") }, ct);
        var manager = new TenantManager(
            NullLogger<TenantManager>.Instance, store, [new TenantDefinitionsCheck()], Catalog(store), Options.Create(new OidcOptions()), store);

        var created = await manager.CreateAsync(
            new TenantDefinition { Id = "initech", Issuer = new Uri("https://initech.example.com") }, ct);
        var acme = Assert.Single(store.Tenants);
        var moved = await manager.UpdateAsync(
            new TenantDefinition { Id = "acme", Issuer = new Uri("https://initech.example.com") }, acme.Version, ct);

        Assert.True(created.TryGetFailure(out var notCreated));
        Assert.Equal(TenantChangeRefusalReason.IssuerNotLicensed, notCreated.Reason);
        Assert.True(moved.TryGetFailure(out var notMoved));
        Assert.Equal(TenantChangeRefusalReason.IssuerNotLicensed, notMoved.Reason);
        Assert.Equal(new Uri("https://acme.example.com"), Assert.Single(store.Tenants).Tenant.Issuer);
    }

    /// <summary>
    /// The settings declaring more tenants than the issuers the license allows stop the server at startup, rather
    /// than leaving the tenant asked last to be refused on every request.
    /// </summary>
    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    public async Task Settings_declaring_more_tenants_than_the_license_allows_stop_the_server(
        int issuerLimit,
        bool starts)
    {
        TestLicense.InstallWithIssuerLimit(issuerLimit);
        var loading = new LicenseLoading();
        loading.Complete();

        var refusal = await Record.ExceptionAsync(
            () => StartupCheck(loading).StartAsync(TestContext.Current.CancellationToken));

        if (starts)
            Assert.Null(refusal);
        else
            Assert.IsType<OptionsValidationException>(refusal);
    }

    /// <summary>
    /// The check waits for the license to be loaded, so a host starting its services at once cannot have it judge the
    /// tenants by the limits of an installation with no license.
    /// </summary>
    [Fact]
    public async Task The_tenants_are_judged_once_the_license_is_loaded()
    {
        TestLicense.InstallWithIssuerLimit(1);
        var loading = new LicenseLoading();

        var started = StartupCheck(loading).StartAsync(TestContext.Current.CancellationToken);
        Assert.False(started.IsCompleted);

        loading.Complete();
        await Assert.ThrowsAsync<OptionsValidationException>(() => started);
    }

    /// <summary>
    /// With a store of the host's own the tenants the settings declare are not served, so the license does not judge
    /// them.
    /// </summary>
    [Fact]
    public async Task Tenants_the_settings_declare_but_a_host_store_replaces_are_not_judged()
    {
        TestLicense.InstallWithIssuerLimit(1);
        var loading = new LicenseLoading();
        loading.Complete();

        await StartupCheck(loading, new WritableTenantStore()).StartAsync(TestContext.Current.CancellationToken);
    }

    private static TenantLicenseStartupCheck StartupCheck(
        LicenseLoading loading,
        ITenantStore? store = null,
        TimeProvider? clock = null)
    {
        var options = Options.Create(new OidcOptions
        {
            Tenants =
            [
                new TenantDefinition { Id = "acme", Issuer = new Uri("https://acme.example.com") },
                new TenantDefinition { Id = "globex", Issuer = new Uri("https://globex.example.com") },
            ],
        });
        return new TenantLicenseStartupCheck(options, store ?? new OptionsTenantStore(options), clock ?? TimeProvider.System, loading);
    }

    /// <summary>
    /// A license that never arrives refuses the start once the wait is over, rather than keeping the server from
    /// starting with nothing in the log.
    /// </summary>
    [Fact]
    public async Task A_license_that_never_arrives_refuses_the_start_once_the_wait_is_over()
    {
        var clock = new FakeTimeProvider();
        var started = StartupCheck(new LicenseLoading(), clock: clock).StartAsync(TestContext.Current.CancellationToken);

        clock.Advance(TenantLicenseStartupCheck.LicenseWait);

        await Assert.ThrowsAsync<InvalidOperationException>(() => started);
    }

    /// <summary>
    /// A license that failed to load refuses the start through its own loading, so the check does not repeat it.
    /// </summary>
    [Fact]
    public async Task A_license_that_failed_to_load_is_left_to_its_loading()
    {
        TestLicense.InstallWithIssuerLimit(1);
        var loading = new LicenseLoading();
        loading.Fail(new InvalidOperationException("The license could not be read."));

        await StartupCheck(loading).StartAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// A provider of the license failing on a timeout of its own is a failed load, not a wait run out, so the start is
    /// not refused with advice about the order of registration.
    /// </summary>
    [Fact]
    public async Task A_license_provider_timing_out_is_left_to_its_loading()
    {
        TestLicense.InstallWithIssuerLimit(1);
        var loading = new LicenseLoading();
        loading.Fail(new TimeoutException("The license provider did not answer."));

        await StartupCheck(loading).StartAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// A tenant left on an issuer a narrower license no longer names can still be changed in other ways, its keys or
    /// clients, while the license is renewed.
    /// </summary>
    [Fact]
    public async Task A_tenant_on_an_issuer_the_license_no_longer_names_can_still_be_changed_in_place()
    {
        var ct = TestContext.Current.CancellationToken;
        TestLicense.ClearChecker();
        LicenseChecker.AddLicense(new License
        {
            ValidIssuers = ["https://globex.example.com"],
            NotBefore = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero),
        });
        var store = new WritableTenantStore();
        await store.AddAsync(new TenantDefinition { Id = "acme", Issuer = new Uri("https://acme.example.com") }, ct);
        var manager = new TenantManager(
            NullLogger<TenantManager>.Instance, store, [new TenantDefinitionsCheck()], Catalog(store), Options.Create(new OidcOptions()), store);

        var changed = await manager.UpdateAsync(
            new TenantDefinition
            {
                Id = "acme",
                Issuer = new Uri("https://acme.example.com"),
                LoginUri = new Uri("/sign-in", UriKind.Relative),
            },
            Assert.Single(store.Tenants).Version,
            ct);

        Assert.True(changed.TryGetSuccess(out _));
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
            Assert.True(Issues(client, AtTheHost));
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
            Assert.True(Issues(tolerated, AtTheHost));
        }

        // Past it: a client never seen before is refused, every time it asks.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            Assert.False(Issues(new ClientInfo("one-client-too-many"), AtTheHost));
        }
    }

    /// <summary>
    /// A license narrowing under the issuers already served leaves the deployment beyond its terms, and every issuer
    /// is refused, the ones counted before included.
    /// </summary>
    [Fact]
    public void Issuers_served_under_a_license_that_narrows_beneath_them_are_all_refused()
    {
        TestLicense.InstallWithIssuerLimit(2);
        Assert.Equal(TestLicense.Issuer, LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
        Assert.Equal(UnlicensedIssuer, LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));

        TestLicense.ReplaceWithIssuerLimit(1);

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(TestLicense.Issuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
    }

    /// <summary>
    /// Issuers asking at once for the last place under the limit take it one at a time, so exactly one is served.
    /// </summary>
    [Fact]
    public async Task Issuers_asking_at_once_for_the_last_place_are_served_one()
    {
        const int Asking = 8;
        const int Rounds = 50;
        for (var round = 0; round < Rounds; round++)
        {
            ArrangeLicenceThatCountsIssuers();
            using var start = new Barrier(Asking);
            var served = 0;
            var asking = Enumerable.Range(0, Asking).Select(index => Task.Run(() =>
            {
                start.SignalAndWait(TestContext.Current.CancellationToken);
                try
                {
                    LicenseChecker.CheckIssuer($"https://issuer-{index}.example.com", SingleIssuer.Tenant, SingleIssuer.HostCatalog);
                    Interlocked.Increment(ref served);
                }
                catch (LicenseViolationException)
                {
                    // Every issuer but one is refused, which is what is being counted
                }
            }));

            await Task.WhenAll(asking);
            Assert.Equal(1, served);
        }
    }

    /// <summary>
    /// An issuer refused past the limit takes no place, so the one freed by a tenant gone for good goes to whichever
    /// issuer asks next rather than to the one that was refused earlier.
    /// </summary>
    [Fact]
    public async Task An_issuer_refused_past_the_limit_takes_no_place_freed_later()
    {
        ArrangeInstallationWithNoLicence();
        var creations = new Creations();
        Assert.Equal(TestLicense.Issuer, CheckIssuer(TestLicense.Issuer, await creations.CreateAsync("acme")));
        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));

        await creations.DropAsync("acme");

        Assert.Equal(ThirdIssuer, LicenseChecker.CheckIssuer(ThirdIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
    }

    [Fact]
    public async Task The_clients_of_a_tenant_gone_for_good_no_longer_count_toward_the_client_limit()
    {
        ArrangeClientLimitOfTwo();
        var creations = new Creations();
        var gone = await creations.CreateAsync("acme");
        var globex = await creations.CreateAsync("globex", GlobexIssuer);

        // Past the margin with the clients of a tenant about to go
        for (var index = 0; index < 3; index++)
        {
            var client = new ClientInfo($"client-{index}");
            Assert.True(Issues(client, gone));
        }

        Assert.False(Issues(new ClientInfo("newcomer"), globex));

        await creations.DropAsync("acme");
        var newcomer = new ClientInfo("newcomer");
        Assert.True(Issues(newcomer, globex));
    }

    [Fact]
    public async Task A_tenant_created_again_keeps_its_place_when_its_earlier_creation_is_released()
    {
        // A tenant removed and created again under its id is served by the new creation while the earlier one
        // still awaits release; that release must not take the place the new creation holds
        ArrangeInstallationWithNoLicence();
        var creations = new Creations();

        CheckIssuer(TestLicense.Issuer, await creations.CreateAsync("acme"));
        CheckIssuer(TestLicense.Issuer, await creations.CreateAsync("acme", generation: "g2"));
        await creations.PassThePeriodAsync();

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
    }

    [Fact]
    public async Task A_tenant_created_again_keeps_its_place_while_requests_of_the_earlier_creation_finish()
    {
        // Requests of both creations are served during the pause: whichever counted last, the release of the
        // earlier creation leaves the place the later one holds
        ArrangeInstallationWithNoLicence();
        var creations = new Creations();
        var earlier = await creations.CreateAsync("acme");

        CheckIssuer(TestLicense.Issuer, earlier);
        CheckIssuer(TestLicense.Issuer, await creations.CreateAsync("acme", generation: "g2"));
        CheckIssuer(TestLicense.Issuer, earlier);
        await creations.PassThePeriodAsync();

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
    }

    [Fact]
    public async Task A_late_request_of_a_released_creation_neither_counts_nor_frees_the_place_of_the_live_one()
    {
        // A request still holding a creation released already carries a canceled token while the catalog remembers
        // the release: it counts for nothing, and the creation serving the tenant now keeps its place
        ArrangeInstallationWithNoLicence();
        var creations = new Creations();
        var earlier = await creations.CreateAsync("acme");
        CheckIssuer(TestLicense.Issuer, earlier);
        CheckIssuer(TestLicense.Issuer, await creations.CreateAsync("acme", generation: "g2"));
        await creations.PassThePeriodAsync();

        CheckIssuer(TestLicense.Issuer, earlier);

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));

        // Nor does it hold the place once the live creation goes
        await creations.DropAsync("acme");
        Assert.Equal(UnlicensedIssuer, LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
    }

    [Fact]
    public async Task A_tenant_moved_to_another_address_keeps_one_place()
    {
        // Through the server's own catalog: the issuers of a deployment of tenants are counted by tenant, so the
        // address a tenant left does not take a place beside the one it serves now, and a request resolved before
        // the move, still carrying the address it left, is counted as the same tenant
        ArrangeInstallationWithNoLicence();
        var ct = TestContext.Current.CancellationToken;
        StoredTenant[] listed = [Acme("1")];
        var store = new Mock<ITenantStore>();
        store.Setup(s => s.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => listed);
        var catalog = Catalog(store.Object);
        await catalog.RefreshAsync(ct);
        var before = (await catalog.FindByIdAsync("acme", ct))!;
        CheckIssuer(TestLicense.Issuer, Resolved(catalog, before));

        listed =
        [
            new StoredTenant(
                new TenantDefinition { Id = before.Id, Issuer = new Uri(UnlicensedIssuer), Generation = before.Generation },
                "2"),
        ];
        await catalog.RefreshAsync(ct);
        var after = (await catalog.FindByIdAsync("acme", ct))!;

        Assert.Equal(UnlicensedIssuer, CheckIssuer(UnlicensedIssuer, Resolved(catalog, after)));
        Assert.Equal(TestLicense.Issuer, CheckIssuer(TestLicense.Issuer, Resolved(catalog, before)));
    }

    [Fact]
    public async Task A_tenant_entered_under_a_served_id_at_another_issuer_takes_a_place_of_its_own()
    {
        // The server vouches only for the definition its catalog serves: a tenant a host enters under the id of a
        // served one, at an issuer that one does not declare, is counted by its issuer like any other
        ArrangeInstallationWithNoLicence();
        var ct = TestContext.Current.CancellationToken;
        var store = new Mock<ITenantStore>();
        store.Setup(s => s.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync([Acme("1")]);
        var catalog = Catalog(store.Object);
        await catalog.RefreshAsync(ct);
        var served = (await catalog.FindByIdAsync("acme", ct))!;
        CheckIssuer(TestLicense.Issuer, Resolved(catalog, served));

        var entered = new TenantDefinition
        {
            Id = served.Id,
            Issuer = new Uri(UnlicensedIssuer),
            Generation = served.Generation,
        };

        var refusal = Assert.Throws<LicenseViolationException>(
            () => CheckIssuer(UnlicensedIssuer, Resolved(catalog, entered)));
        Assert.Equal(LicenseRefusalReasons.IssuerLimit, refusal.Reason);
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
            new(new TenantDefinition { Id = "acme", Issuer = new Uri(TestLicense.Issuer), Generation = "g1" }, "1"),
        };
        var store = new Mock<ITenantStore>();
        store.Setup(s => s.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => listed.ToArray());
        var time = new FakeTimeProvider();
        var catalog = Catalog(store.Object, time);
        await catalog.RefreshAsync(ct);
        var acme = Resolved(catalog, (await catalog.FindByIdAsync("acme", ct))!);
        CheckIssuer(TestLicense.Issuer, acme);

        listed.Clear();
        await catalog.RefreshAsync(ct);
        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));

        time.Advance(new OidcOptions().RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);
        Assert.Equal(UnlicensedIssuer, LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
    }

    [Fact]
    public async Task An_address_a_tenant_left_counts_as_the_tenant_for_one_refresh_period()
    {
        // A request resolved before the move is counted as the tenant while the catalog's next readings still let it
        // finish; past one refresh period the address it carries is counted as an issuer of its own
        ArrangeInstallationWithNoLicence();
        var ct = TestContext.Current.CancellationToken;
        var (catalog, time, listed) = await ServedAtAsync(TestLicense.Issuer, ct);
        var before = (await catalog.FindByIdAsync("acme", ct))!;
        CheckIssuer(TestLicense.Issuer, Resolved(catalog, before));

        listed[0] = AcmeAt(UnlicensedIssuer, "2");
        await catalog.RefreshAsync(ct);
        Assert.Equal(TestLicense.Issuer, CheckIssuer(TestLicense.Issuer, Resolved(catalog, before)));

        time.Advance(new OidcOptions().RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);
        var refusal = Assert.Throws<LicenseViolationException>(
            () => CheckIssuer(TestLicense.Issuer, Resolved(catalog, before)));
        Assert.Equal(LicenseRefusalReasons.IssuerLimit, refusal.Reason);
    }

    [Fact]
    public async Task An_address_a_tenant_moved_back_to_counts_as_the_tenant_past_the_period()
    {
        ArrangeInstallationWithNoLicence();
        var ct = TestContext.Current.CancellationToken;
        var (catalog, time, listed) = await ServedAtAsync(TestLicense.Issuer, ct);
        CheckIssuer(TestLicense.Issuer, Resolved(catalog, (await catalog.FindByIdAsync("acme", ct))!));

        listed[0] = AcmeAt(UnlicensedIssuer, "2");
        await catalog.RefreshAsync(ct);
        listed[0] = AcmeAt(TestLicense.Issuer, "3");
        await catalog.RefreshAsync(ct);
        time.Advance(new OidcOptions().RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);

        var back = (await catalog.FindByIdAsync("acme", ct))!;
        Assert.Equal(TestLicense.Issuer, CheckIssuer(TestLicense.Issuer, Resolved(catalog, back)));
    }

    [Fact]
    public async Task An_address_a_tenant_left_long_ago_frees_its_place_with_the_tenant()
    {
        // Counted by its issuer once past the period, the address the tenant left still belongs to that creation, so
        // the place it takes is freed when the catalog releases the tenant rather than held for the life of the process
        TestLicense.InstallWithIssuerLimit(2);
        var ct = TestContext.Current.CancellationToken;
        var (catalog, time, listed) = await ServedAtAsync(TestLicense.Issuer, ct);
        var before = (await catalog.FindByIdAsync("acme", ct))!;
        CheckIssuer(TestLicense.Issuer, Resolved(catalog, before));

        listed[0] = AcmeAt(UnlicensedIssuer, "2");
        await catalog.RefreshAsync(ct);
        time.Advance(new OidcOptions().RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);
        CheckIssuer(TestLicense.Issuer, Resolved(catalog, before));
        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer(ThirdIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));

        listed.Clear();
        await catalog.RefreshAsync(ct);
        time.Advance(new OidcOptions().RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);

        // Both places are free again: the tenant's and the one its former address took
        Assert.Equal(ThirdIssuer, LicenseChecker.CheckIssuer(ThirdIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
        Assert.Equal(UnlicensedIssuer, LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
    }

    /// <summary>
    /// A client removed through registration at an address its tenant's creation was never served at keeps its place:
    /// the server does not vouch that this request is the tenant the client was counted with.
    /// </summary>
    [Fact]
    public async Task A_client_removed_at_an_address_its_tenant_is_not_served_at_keeps_the_tenants_place()
    {
        ArrangeClientLimitOfTwo();
        var ct = TestContext.Current.CancellationToken;
        var (catalog, _, _) = await ServedAtAsync(TestLicense.Issuer, ct);
        var served = (await catalog.FindByIdAsync("acme", ct))!;
        var removed = new RegisteredClient(new ClientInfo("client-0"), "jti");
        CountPastTheMargin(Resolved(catalog, served), removed.ClientInfo);

        var entered = new TenantDefinition
        {
            Id = served.Id,
            Issuer = new Uri(UnlicensedIssuer),
            Generation = served.Generation,
        };
        await RemoveThroughRegistrationAsync(removed, new Served(entered, catalog, UnlicensedIssuer));

        Assert.False(Issues(new ClientInfo("newcomer"), Resolved(catalog, served)));
    }

    /// <summary>
    /// The clients counted at an address the server does not vouch for are counted with that address, and a removal
    /// through registration there does not take them off the count.
    /// </summary>
    [Fact]
    public async Task A_client_removed_at_an_address_it_was_counted_with_keeps_its_place()
    {
        ArrangeClientLimitOfTwo();
        var ct = TestContext.Current.CancellationToken;
        var (catalog, _, _) = await ServedAtAsync(TestLicense.Issuer, ct);
        var served = (await catalog.FindByIdAsync("acme", ct))!;
        var entered = new Served(
            new TenantDefinition { Id = served.Id, Issuer = new Uri(UnlicensedIssuer), Generation = served.Generation },
            catalog,
            UnlicensedIssuer);
        var removed = new RegisteredClient(new ClientInfo("client-0"), "jti");
        CountPastTheMargin(entered, removed.ClientInfo);

        await RemoveThroughRegistrationAsync(removed, entered);

        Assert.False(Issues(new ClientInfo("newcomer"), entered));
    }

    private static StoredTenant AcmeAt(string issuer, string version)
        => new(new TenantDefinition { Id = "acme", Issuer = new Uri(issuer), Generation = "g1" }, version);

    private static async Task<(StoreTenantCatalog Catalog, FakeTimeProvider Time, List<StoredTenant> Listed)>
        ServedAtAsync(string issuer, CancellationToken ct)
    {
        var listed = new List<StoredTenant> { AcmeAt(issuer, "1") };
        var store = new Mock<ITenantStore>();
        store.Setup(s => s.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => listed.ToArray());
        var time = new FakeTimeProvider();
        var catalog = Catalog(store.Object, time);
        await catalog.RefreshAsync(ct);
        return (catalog, time, listed);
    }

    [Fact]
    public async Task A_late_request_of_a_tenant_the_catalog_released_takes_back_no_place()
    {
        // Through the server's own catalog: a request still holding a released tenant is the same creation, so it is
        // neither counted again nor counted by its issuer, and the place the release freed stays free
        ArrangeInstallationWithNoLicence();
        var ct = TestContext.Current.CancellationToken;
        var listed = new List<StoredTenant>
        {
            new(new TenantDefinition { Id = "acme", Issuer = new Uri(TestLicense.Issuer), Generation = "g1" }, "1"),
        };
        var store = new Mock<ITenantStore>();
        store.Setup(s => s.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => listed.ToArray());
        var time = new FakeTimeProvider();
        var catalog = Catalog(store.Object, time);
        await catalog.RefreshAsync(ct);
        var acme = Resolved(catalog, (await catalog.FindByIdAsync("acme", ct))!);
        CheckIssuer(TestLicense.Issuer, acme);

        listed.Clear();
        await catalog.RefreshAsync(ct);
        time.Advance(new OidcOptions().RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);
        CheckIssuer(TestLicense.Issuer, acme);

        Assert.Equal(UnlicensedIssuer, LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
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
        var acme = Resolved(catalog, (await catalog.FindByIdAsync("acme", ct))!);
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
        var creations = new Creations();
        var acme = await creations.CreateAsync("acme");
        var globex = await creations.CreateAsync("globex", GlobexIssuer);
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
        var acme = Resolved(catalog, (await catalog.FindByIdAsync("acme", ct))!);
        foreach (var client in listed[0].Tenant.Clients)
            _ = Issues(client, acme);
        Assert.False(Issues(new ClientInfo("newcomer"), acme));

        listed = [Acme("2", "client-1", "client-2")];
        await catalog.RefreshAsync(ct);

        AssertOnePlaceFree(acme);
    }

    /// <summary>
    /// Counts <paramref name="first"/> and two more clients of <paramref name="issuer"/>, past the margin over a
    /// limit of two, so a newcomer is refused.
    /// </summary>
    private static void CountPastTheMargin(Served issuer, ClientInfo first)
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
    private static void AssertOnePlaceFree(Served issuer)
    {
        var newcomer = new ClientInfo("newcomer");
        Assert.True(Issues(newcomer, issuer));
        Assert.False(Issues(new ClientInfo("newcomer-2"), issuer));
    }

    /// <summary>
    /// Whether a token can be issued to <paramref name="client"/> at <paramref name="served"/>: the check that counts
    /// the client, run where a token names its issuer, which is the one the tenant is served at unless
    /// <paramref name="issuer"/> names another.
    /// </summary>
    private static bool Issues(ClientInfo client, Served served, string? issuer = null)
    {
        try
        {
            LicenseChecker.CheckLicense(issuer ?? served.Issuer, served.Tenant, served.ResolvedBy, client.ClientId);
            return true;
        }
        catch (LicenseViolationException)
        {
            return false;
        }
    }

    private static async Task RemoveThroughRegistrationAsync(RegisteredClient removed, Served served)
    {
        var clients = new Mock<IClientInfoManager>();
        clients.Setup(manager => manager.TryRemoveClientAsync(It.IsAny<TenantDefinition>(), removed)).ReturnsAsync(true);
        var result = await new RemoveClientRequestProcessor(
                clients.Object,
                TimeProvider.System,
                served.ResolvedBy)
            .ProcessAsync(served.Tenant, new ValidClientRequest(new ClientRequest(), removed));
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
            Issuer = new Uri(TestLicense.Issuer),
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
            Options.Create(new OidcOptions()),
            time ?? new FakeTimeProvider());
    }

    /// <summary>
    /// The tenant a request was resolved to, the catalog it was resolved from, and the issuer its tokens name.
    /// </summary>
    private sealed record Served(TenantDefinition Tenant, ITenantCatalog ResolvedBy, string Issuer);

    /// <summary>A request <paramref name="catalog"/> resolved to <paramref name="tenant"/>, served at the licensed issuer.</summary>
    private static Served Resolved(StoreTenantCatalog catalog, TenantDefinition tenant)
        => new(tenant, catalog, TestLicense.Issuer);

    /// <summary>A request to the tenant <paramref name="id"/> a catalog of the host's own resolved.</summary>
    private static Served AtTheHostsOwn(string id)
        => new(new TenantDefinition { Id = id, Issuer = new Uri(TestLicense.Issuer) }, SingleIssuer.HostCatalog, TestLicense.Issuer);

    /// <summary>A request to the tenant a test describes nothing of, which a catalog of the host's own resolved.</summary>
    private static Served AtTheHost => new(SingleIssuer.Tenant, SingleIssuer.HostCatalog, TestLicense.Issuer);

    private static string CheckIssuer(string issuer, Served served)
        => LicenseChecker.CheckIssuer(issuer, served.Tenant, served.ResolvedBy);

    /// <summary>
    /// The server's own catalog over a store a test lists tenants into: a creation is served once listed, and released
    /// once the store no longer holds it and one refresh period has passed, as the catalog releases it in production.
    /// </summary>
    private sealed class Creations
    {
        private readonly List<StoredTenant> _listed = [];
        private readonly FakeTimeProvider _time = new();
        private readonly StoreTenantCatalog _catalog;

        public Creations()
        {
            var store = new Mock<ITenantStore>();
            store.Setup(s => s.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => _listed.ToArray());
            _catalog = Catalog(store.Object, _time);
        }

        /// <summary>
        /// Lists the creation <paramref name="generation"/> of <paramref name="id"/> at <paramref name="issuer"/> in
        /// place of any other of that id, and resolves a request to it.
        /// </summary>
        public async Task<Served> CreateAsync(string id, string issuer = TestLicense.Issuer, string generation = "g1")
        {
            var ct = TestContext.Current.CancellationToken;
            _listed.RemoveAll(stored => stored.Tenant.Id == id);
            _listed.Add(new StoredTenant(
                new TenantDefinition { Id = id, Issuer = new Uri(issuer), Generation = generation },
                generation));
            await _catalog.RefreshAsync(ct);
            return new Served((await _catalog.FindByIdAsync(id, ct))!, _catalog, issuer);
        }

        /// <summary>Drops <paramref name="id"/> from the store and lets the catalog release it.</summary>
        public async Task DropAsync(string id)
        {
            _listed.RemoveAll(stored => stored.Tenant.Id == id);
            await _catalog.RefreshAsync(TestContext.Current.CancellationToken);
            await PassThePeriodAsync();
        }

        /// <summary>Lets one refresh period pass, so the catalog releases every creation the store no longer holds.</summary>
        public async Task PassThePeriodAsync()
        {
            _time.Advance(new OidcOptions().RefreshTenantsEvery);
            await _catalog.RefreshAsync(TestContext.Current.CancellationToken);
        }
    }

    /// <summary>
    /// A catalog a host registers is asked nothing by the license, so it can neither say a tenant is gone nor that two
    /// issuers are one tenant: a tenant it resolved stays counted, and the second issuer past a limit of one is
    /// refused.
    /// </summary>
    [Fact]
    public void A_catalog_of_the_hosts_own_is_asked_nothing_and_its_tenant_stays_counted()
    {
        ArrangeLicenceThatCountsIssuers();
        var hosts = new Mock<ITenantCatalog>(MockBehavior.Strict);
        var acme = new TenantDefinition { Id = "acme", Issuer = new Uri("https://acme.example.com") };

        LicenseChecker.CheckIssuer("https://acme.example.com", acme, hosts.Object);

        Assert.Throws<LicenseViolationException>(
            () => LicenseChecker.CheckIssuer("https://globex.example.com", acme, hosts.Object));
    }

    /// <summary>
    /// A catalog a host registers does not tell the license which tenant a client belongs to: a client id two issuers
    /// serve takes a place under each issuer the tokens name.
    /// </summary>
    [Fact]
    public void Clients_of_a_tenant_a_catalog_of_the_hosts_own_resolved_are_counted_with_the_issuer_of_the_token()
    {
        ArrangeClientLimitOfTwo();
        var sameId = AtTheHostsOwn("acme");

        _ = Issues(new ClientInfo("web"), sameId, "https://acme.example.com");
        _ = Issues(new ClientInfo("web"), sameId, "https://globex.example.com");
        _ = Issues(new ClientInfo("mobile"), sameId, "https://acme.example.com");

        Assert.False(Issues(new ClientInfo("mobile"), sameId, "https://globex.example.com"));
    }

    /// <summary>
    /// The clients of a tenant a catalog of the host's own resolved stay counted: the license asks that catalog
    /// nothing, so it cannot take them off the count.
    /// </summary>
    [Fact]
    public void Clients_of_a_tenant_a_catalog_of_the_hosts_own_resolved_stay_counted()
    {
        ArrangeClientLimitOfTwo();
        var hosts = new Mock<ITenantCatalog>(MockBehavior.Strict);

        CountPastTheMargin(
            new Served(new TenantDefinition { Id = "acme", Issuer = new Uri(TestLicense.Issuer) }, hosts.Object, TestLicense.Issuer),
            new ClientInfo("client-0"));
    }

    /// <summary>
    /// A client removed through registration at a tenant a catalog of the host's own resolved stays counted: the
    /// license cannot tell which of the issuers that tenant is served at it was counted with, even when its id spells
    /// the issuer itself.
    /// </summary>
    [Fact]
    public async Task A_client_removed_at_a_tenant_a_catalog_of_the_hosts_own_resolved_keeps_its_place()
    {
        ArrangeClientLimitOfTwo();
        var hosts = AtTheHostsOwn(TestLicense.Issuer);
        var removed = new RegisteredClient(new ClientInfo("client-0"), "jti");
        CountPastTheMargin(hosts, removed.ClientInfo);

        await RemoveThroughRegistrationAsync(removed, hosts);

        Assert.False(Issues(new ClientInfo("newcomer"), hosts));
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
            _ = Issues(new ClientInfo($"established-{index}"), AtTheHost);
        }

        Assert.False(Issues(new ClientInfo("newcomer"), AtTheHost));

        var established = new ClientInfo("established-0");
        Assert.True(Issues(established, AtTheHost));
    }

    [Fact]
    public async Task A_client_id_two_tenants_register_counts_once_for_each()
    {
        // Two tenants may each register a client under one id, and each is a client the deployment serves. Counted
        // by the bare id, the second tenant's clients would ride on the first's and never reach the limit.
        ArrangeClientLimitOfTwo();
        var creations = new Creations();
        var acme = await creations.CreateAsync("acme");
        var globex = await creations.CreateAsync("globex", GlobexIssuer);

        _ = Issues(new ClientInfo("web"), acme);
        _ = Issues(new ClientInfo("web"), globex);
        _ = Issues(new ClientInfo("mobile"), acme);

        Assert.False(Issues(new ClientInfo("mobile"), globex));
    }

    [Fact]
    public async Task A_refusal_is_recorded_for_each_tenant_refusing_a_client_of_one_id()
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
        var creations = new Creations();
        var acme = await creations.CreateAsync("acme");
        var globex = await creations.CreateAsync("globex", GlobexIssuer);
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
                () => LicenseChecker.CheckIssuer(UnlicensedIssuer, SingleIssuer.Tenant, SingleIssuer.HostCatalog));
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
