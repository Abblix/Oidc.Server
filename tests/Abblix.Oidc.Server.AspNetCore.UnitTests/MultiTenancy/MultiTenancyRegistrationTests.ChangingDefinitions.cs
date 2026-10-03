// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections;
using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

public partial class MultiTenancyRegistrationTests
{
    /// <summary>
    /// A tenant whose definition changes while the server runs - read again from a store of tenants - is served
    /// the clients the new definition declares: one it dropped no longer authenticates, one it added does.
    /// </summary>
    [Fact]
    public async Task TenantsChangedDefinition_ServesClientsItNowDeclares()
    {
        TenantDefinition Acme(string clientId)
            => new() { Id = "acme", Issuer = AcmeIssuer, Clients = [new ClientInfo(clientId)] };

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddClientInformation();
        services.AddServerStorage().AddMultiTenancy(_ => { });
        using var provider = services.BuildServiceProvider();
        var clients = provider.GetRequiredService<IClientInfoProvider>();

        EnterTenant(provider, Acme("before"));
        Assert.NotNull(await clients.TryFindClientAsync("before"));

        EnterTenant(provider, Acme("after"));
        Assert.Null(await clients.TryFindClientAsync("before"));
        Assert.NotNull(await clients.TryFindClientAsync("after"));
    }

    /// <summary>
    /// What was built for a tenant is kept while the tenant stays in the store, through one reading that no longer
    /// finds it, and is let go once it is released: a request still holding the tenant builds it again.
    /// </summary>
    [Fact]
    public async Task WhatWasBuiltForATenant_IsLetGo_OnceTheTenantIsReleased()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var acme = await Served(provider, store, AcmeWithoutClients(), "1");
        EnterTenant(provider, acme);
        var local = provider.GetRequiredService<IIssuerLocal<object>>();
        var built = local.GetOrCreate(null, () => new object());
        var catalog = provider.GetRequiredService<StoreTenantCatalog>();

        store.Tenants = [];
        await catalog.RefreshAsync(CancellationToken.None);
        Assert.Same(built, local.GetOrCreate(null, () => new object()));

        ((FakeTimeProvider)provider.GetRequiredService<TimeProvider>()).Advance(new MultiTenancyOptions().RefreshEvery);
        await catalog.RefreshAsync(CancellationToken.None);
        Assert.NotSame(built, local.GetOrCreate(null, () => new object()));
    }

    /// <summary>
    /// Multi-tenancy registers the manager of the tenants; over a store the host writes to by other means it says
    /// the store has no writer rather than fail on something else.
    /// </summary>
    [Fact]
    public async Task TheManagerOfTheTenants_IsRegistered_AndNamesAMissingWriter()
    {
        using var provider = ServingFrom(new ChangingTenantStore());

        var manager = provider.GetRequiredService<ITenantManager>();

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => manager.CreateAsync(AcmeWithoutClients(), CancellationToken.None));
        Assert.Contains(nameof(ITenantStoreWriter), refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A store of tenants whose listing changes between readings, as one the host edits while the server runs.
    /// </summary>
    private sealed class ChangingTenantStore : ITenantStore
    {
        public IReadOnlyCollection<StoredTenant> Tenants { get; set; } = [];

        public Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
            => Task.FromResult(Tenants);
    }

    /// <summary>
    /// A catalog of the host's own: it passes on what the server's catalog serves until the host hands out a
    /// definition of its own.
    /// </summary>
    private sealed class HostCatalog(StoreTenantCatalog inner) : ITenantCatalog
    {
        public TenantDefinition? Own { get; set; }

        public async ValueTask<TenantDefinition?> FindByIdAsync(string tenantId, CancellationToken cancellationToken)
            => Own ?? await inner.FindByIdAsync(tenantId, cancellationToken);

        public async ValueTask<TenantDefinition?> FindByAddressAsync(
            string host,
            string path,
            CancellationToken cancellationToken)
            => Own ?? await inner.FindByAddressAsync(host, path, cancellationToken);
    }

    private static ServiceProvider ServingFrom(ChangingTenantStore store, bool hostCatalog = false)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddClientInformation();
        services.AddSingleton<ITenantStore>(store);
        services.AddSingleton<TimeProvider>(new FakeTimeProvider());
        if (hostCatalog)
        {
            services.AddSingleton<HostCatalog>();
            services.AddSingleton<ITenantCatalog>(serviceProvider => serviceProvider.GetRequiredService<HostCatalog>());
        }

        services.AddServerStorage().AddMultiTenancy(_ => { });
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// The definition the server serves once the store holds <paramref name="tenant"/> under
    /// <paramref name="version"/> and has been read again.
    /// </summary>
    private static async Task<TenantDefinition> Served(
        IServiceProvider provider,
        ChangingTenantStore store,
        TenantDefinition tenant,
        string version)
    {
        store.Tenants = [new StoredTenant(tenant, version)];
        var catalog = provider.GetRequiredService<StoreTenantCatalog>();
        await catalog.RefreshAsync(CancellationToken.None);
        var served = await catalog.FindByIdAsync(tenant.Id, CancellationToken.None);
        Assert.NotNull(served);
        return served;
    }

    // Declares no clients at all, so it hands out the empty list every such definition shares
    private static TenantDefinition AcmeWithoutClients() => new() { Id = "acme", Issuer = AcmeIssuer };

    private static TenantDefinition AcmeWith(params string[] clientIds) => new()
    {
        Id = "acme",
        Issuer = AcmeIssuer,
        Clients =
        [
            ..clientIds.Select(id => new ClientInfo(id) { TokenEndpointAuthMethod = ClientAuthenticationMethods.None }),
        ],
    };

    /// <summary>
    /// A request begun before a tenant's definition changed holds the former one to its end; reaching the client
    /// store then, it does not bring the former definition back and drop a client registered under an id the new
    /// definition freed.
    /// </summary>
    [Fact]
    public async Task RequestHoldingFormerDefinition_KeepsRegistrationMadeSince()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith("freed"), "1");
        EnterTenant(provider, former);
        Assert.NotNull(await clients.TryFindClientAsync("freed"));

        var current = await Served(provider, store, AcmeWith(), "2");
        EnterTenant(provider, current);
        Assert.True(await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("freed"), "token-id")));

        EnterTenant(provider, former);
        await clients.TryFindClientAsync("freed");

        EnterTenant(provider, current);
        Assert.NotNull(await manager.TryFindRegisteredClientAsync("freed"));
    }

    /// <summary>
    /// A request holding a definition the store replaced twice since does not leave the tenant served the
    /// definition between the two.
    /// </summary>
    [Fact]
    public async Task RequestHoldingMiddleDefinition_IsAnsweredWithLatest()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();

        EnterTenant(provider, await Served(provider, store, AcmeWith("first"), "1"));
        Assert.NotNull(await clients.TryFindClientAsync("first"));
        var between = await Served(provider, store, AcmeWith("between"), "2");
        var last = await Served(provider, store, AcmeWith("last"), "3");
        EnterTenant(provider, last);
        Assert.NotNull(await clients.TryFindClientAsync("last"));

        EnterTenant(provider, between);
        Assert.Null(await clients.TryFindClientAsync("between"));

        EnterTenant(provider, last);
        Assert.NotNull(await clients.TryFindClientAsync("last"));
        Assert.Null(await clients.TryFindClientAsync("between"));
    }

    /// <summary>
    /// A tenant whose clients are all removed stops serving them, although every definition declaring no clients
    /// hands out one and the same empty list.
    /// </summary>
    [Fact]
    public async Task TenantLeftWithoutClients_StopsServingThem()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();

        EnterTenant(provider, await Served(provider, store, AcmeWithoutClients(), "1"));
        Assert.Null(await clients.TryFindClientAsync("removed"));
        EnterTenant(provider, await Served(provider, store, AcmeWith("removed"), "2"));
        Assert.NotNull(await clients.TryFindClientAsync("removed"));

        EnterTenant(provider, await Served(provider, store, AcmeWithoutClients(), "3"));
        Assert.Null(await clients.TryFindClientAsync("removed"));
    }

    /// <summary>
    /// A store handing back, as a new version, a definition object it handed out before - a rollback to a kept
    /// one - has that definition served again.
    /// </summary>
    [Fact]
    public async Task DefinitionHandedBack_IsServedAgain()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var kept = AcmeWith("kept");

        EnterTenant(provider, await Served(provider, store, kept, "1"));
        Assert.NotNull(await clients.TryFindClientAsync("kept"));
        EnterTenant(provider, await Served(provider, store, AcmeWith("replacing"), "2"));
        Assert.NotNull(await clients.TryFindClientAsync("replacing"));

        EnterTenant(provider, await Served(provider, store, kept, "3"));
        Assert.NotNull(await clients.TryFindClientAsync("kept"));
    }

    /// <summary>
    /// Clients a definition declares, whose reading, once armed, stops until the test lets it go on: it holds the
    /// store mid-way through building them.
    /// </summary>
    private sealed class HeldClients(params ClientInfo[] clients) : IEnumerable<ClientInfo>
    {
        // How long a test waits for the other side of a held build before failing rather than hanging
        public static readonly TimeSpan Patience = TimeSpan.FromSeconds(10);

        public bool Armed { get; set; }
        public SemaphoreSlim Reached { get; } = new(0);
        public SemaphoreSlim Released { get; } = new(0);

        public IEnumerator<ClientInfo> GetEnumerator()
        {
            if (Armed)
            {
                Armed = false;
                Reached.Release();
                if (!Released.Wait(Patience))
                    throw new TimeoutException("The test never let the held build go on.");
            }

            return ((IEnumerable<ClientInfo>)clients).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    /// <summary>
    /// A registration under an id the served definition configures, written by a request holding the former one
    /// while the clients of the served one are being built, is answered as not made rather than kept and then
    /// dropped by that build.
    /// </summary>
    [Fact]
    public async Task RegistrationDuringClientsBuild_IsJudgedByServedDefinition()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith(), "1");
        EnterTenant(provider, former);
        Assert.Null(await clients.TryFindClientAsync("taken"));

        var held = new HeldClients(
            new ClientInfo("taken") { TokenEndpointAuthMethod = ClientAuthenticationMethods.None });
        var current = await Served(
            provider, store, new TenantDefinition { Id = "acme", Issuer = AcmeIssuer, Clients = held }, "2");
        held.Armed = true;
        var building = Task.Run(async () =>
        {
            EnterTenant(provider, current);
            return await clients.TryFindClientAsync("taken");
        });
        Assert.True(await held.Reached.WaitAsync(HeldClients.Patience, TestContext.Current.CancellationToken));

        var registering = Task.Run(async () =>
        {
            EnterTenant(provider, former);
            return await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("taken"), "token-id"));
        });
        Assert.False(await registering.WaitAsync(HeldClients.Patience, TestContext.Current.CancellationToken));
        held.Released.Release();

        Assert.NotNull(await building);
    }

    /// <summary>
    /// A registration under an id the served definition configures is answered as not made, though the request
    /// writing it holds the former definition and nobody has built the clients of the served one yet.
    /// </summary>
    [Fact]
    public async Task RegistrationFromFormerDefinition_IsJudgedByServedOne()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith(), "1");
        EnterTenant(provider, former);
        Assert.Null(await clients.TryFindClientAsync("taken"));
        var current = await Served(provider, store, AcmeWith("taken"), "2");

        Assert.False(await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("taken"), "token-id")));

        EnterTenant(provider, current);
        Assert.Null(await manager.TryFindRegisteredClientAsync("taken"));
    }

    /// <summary>
    /// A change to a registration under an id the served definition has come to configure is answered as not made,
    /// though the request writing it holds the former definition and nobody has built the clients of the served one
    /// yet.
    /// </summary>
    [Fact]
    public async Task UpdateFromFormerDefinition_IsJudgedByServedOne()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith(), "1");
        EnterTenant(provider, former);
        var registration = new RegisteredClient(new ClientInfo("taken"), "token-id");
        Assert.True(await manager.TryAddClientAsync(registration));
        await Served(provider, store, AcmeWith("taken"), "2");

        Assert.False(await manager.TryUpdateClientAsync(
            registration,
            new RegisteredClient(new ClientInfo("taken") { ClientName = "changed" }, "token-id")));
    }

    /// <summary>
    /// A build of the former definition's clients, begun before the catalog moved on and ending after, does not
    /// drop a registration made meanwhile under an id the served definition freed.
    /// </summary>
    [Fact]
    public async Task BuildOfFormerDefinitionEndingLate_KeepsRegistrationMadeMeanwhile()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        EnterTenant(provider, await Served(provider, store, AcmeWith(), "1"));
        Assert.Null(await clients.TryFindClientAsync("freed"));
        var held = new HeldClients(
            new ClientInfo("freed") { TokenEndpointAuthMethod = ClientAuthenticationMethods.None });
        var former = await Served(
            provider, store, new TenantDefinition { Id = "acme", Issuer = AcmeIssuer, Clients = held }, "2");
        held.Armed = true;
        var building = Task.Run(async () =>
        {
            EnterTenant(provider, former);
            return await clients.TryFindClientAsync("other");
        });
        Assert.True(await held.Reached.WaitAsync(HeldClients.Patience, TestContext.Current.CancellationToken));

        var current = await Served(provider, store, AcmeWith(), "3");
        var registered = await Task.Run(async () =>
        {
            EnterTenant(provider, current);
            return await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("freed"), "token-id"));
        });
        Assert.True(registered);
        held.Released.Release();
        await building.WaitAsync(HeldClients.Patience, TestContext.Current.CancellationToken);

        EnterTenant(provider, current);
        Assert.NotNull(await manager.TryFindRegisteredClientAsync("freed"));
    }

    /// <summary>
    /// A tenant the store dropped before anybody built the clients of its last definition serves a request holding
    /// that definition its clients, not those of the definition before.
    /// </summary>
    [Fact]
    public async Task TenantDroppedBeforeBuild_ServesClientsOfLastDefinition()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();

        EnterTenant(provider, await Served(provider, store, AcmeWith("removed"), "1"));
        Assert.NotNull(await clients.TryFindClientAsync("removed"));
        var last = await Served(provider, store, AcmeWith(), "2");

        store.Tenants = [];
        await provider.GetRequiredService<StoreTenantCatalog>().RefreshAsync(CancellationToken.None);

        EnterTenant(provider, last);
        Assert.Null(await clients.TryFindClientAsync("removed"));
    }

    /// <summary>
    /// A request holding a definition the served one replaced finds, under an id both configure, the configured
    /// client rather than a registration made before either took the id.
    /// </summary>
    [Fact]
    public async Task RequestHoldingReplacedDefinition_FindsConfiguredClientOverRegistration()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        EnterTenant(provider, await Served(provider, store, AcmeWith(), "1"));
        Assert.Null(await clients.TryFindClientAsync("other"));
        Assert.True(await manager.TryAddClientAsync(
            new RegisteredClient(new ClientInfo("taken") { ClientName = "registrant" }, "token-id")));
        var replaced = await Served(provider, store, AcmeWith("taken"), "2");
        await Served(provider, store, AcmeWith("taken", "more"), "3");

        EnterTenant(provider, replaced);
        var found = await clients.TryFindClientAsync("taken");

        Assert.NotNull(found);
        Assert.NotEqual("registrant", found.ClientName);
    }

    /// <summary>
    /// A request begun before the served definition took an id does not find, under it, a registration made
    /// before: the lookup drops it, as the settings now configure the id.
    /// </summary>
    [Fact]
    public async Task RequestBegunBeforeIdWasTaken_DoesNotFindRegistrationUnderIt()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith(), "1");
        EnterTenant(provider, former);
        Assert.Null(await clients.TryFindClientAsync("other"));
        Assert.True(await manager.TryAddClientAsync(
            new RegisteredClient(new ClientInfo("taken") { ClientName = "registrant" }, "token-id")));
        await Served(provider, store, AcmeWith("taken"), "2");

        EnterTenant(provider, former);

        Assert.Null(await clients.TryFindClientAsync("taken"));
        Assert.Null(await manager.TryFindRegisteredClientAsync("taken"));
    }

    /// <summary>
    /// A registration written by a request holding a definition that configures its id while the served one frees
    /// it is made and kept: the definition in force decides, and it leaves the id free.
    /// </summary>
    [Fact]
    public async Task RegistrationUnderIdOnlyHeldDefinitionConfigures_IsMadeAndKept()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        EnterTenant(provider, await Served(provider, store, AcmeWith(), "1"));
        Assert.Null(await clients.TryFindClientAsync("other"));
        var held = await Served(provider, store, AcmeWith("freed"), "2");
        var current = await Served(provider, store, AcmeWith(), "3");

        EnterTenant(provider, held);
        Assert.True(await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("freed"), "token-id")));

        EnterTenant(provider, current);
        Assert.NotNull(await manager.TryFindRegisteredClientAsync("freed"));
    }

    /// <summary>
    /// A change to a registration, written by a request holding a definition that configured its id while the served
    /// one frees it, is made and kept: the definition in force decides, and it leaves the id free.
    /// </summary>
    [Fact]
    public async Task UpdateUnderIdOnlyHeldDefinitionConfigures_IsMadeAndKept()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        EnterTenant(provider, await Served(provider, store, AcmeWith(), "1"));
        Assert.Null(await clients.TryFindClientAsync("other"));
        var registration = new RegisteredClient(new ClientInfo("freed"), "token-id");
        Assert.True(await manager.TryAddClientAsync(registration));
        var held = await Served(provider, store, AcmeWith("freed"), "2");
        var current = await Served(provider, store, AcmeWith(), "3");

        var changed = new RegisteredClient(new ClientInfo("freed") { ClientName = "changed" }, "token-id");
        EnterTenant(provider, held);
        Assert.True(await manager.TryUpdateClientAsync(registration, changed));

        EnterTenant(provider, current);
        Assert.Same(changed, await manager.TryFindRegisteredClientAsync("freed"));
    }

    /// <summary>
    /// A registration written while the tenant is refused or dropped, by a request holding a definition from before
    /// the last one served, is judged by that last one: an id it configures is answered as not made rather than
    /// kept and dropped once the tenant is served again.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RegistrationFromEarlierDefinitionWhileTenantUnserved_IsJudgedByLastServed(bool refused)
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var catalog = provider.GetRequiredService<StoreTenantCatalog>();
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var earlier = await Served(provider, store, AcmeWith(), "1");
        var last = await Served(provider, store, AcmeWith("taken"), "2");
        EnterTenant(provider, last);
        Assert.NotNull(await clients.TryFindClientAsync("taken"));

        // Globex claims acme's issuer, so the checks refuse both
        store.Tenants = refused
            ?
            [
                new StoredTenant(last, "2"),
                new StoredTenant(new TenantDefinition { Id = "globex", Issuer = AcmeIssuer }, "1"),
            ]
            : [];
        await catalog.RefreshAsync(CancellationToken.None);
        Assert.Null(await catalog.FindByIdAsync("acme", CancellationToken.None));

        EnterTenant(provider, earlier);
        Assert.False(await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("taken"), "token-id")));
    }

    /// <summary>
    /// A registration written by a request holding a definition that configures its id is answered as not made while
    /// the tenant is refused, rather than made and then dropped once the tenant is served again.
    /// </summary>
    [Fact]
    public async Task RegistrationWhileTenantRefused_UnderIdItsDefinitionConfigures_IsNotMade()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var catalog = provider.GetRequiredService<StoreTenantCatalog>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var held = await Served(provider, store, AcmeWith("taken"), "1");

        // Globex claims acme's issuer, so the checks refuse both
        store.Tenants =
        [
            new StoredTenant(held, "1"),
            new StoredTenant(new TenantDefinition { Id = "globex", Issuer = AcmeIssuer }, "1"),
        ];
        await catalog.RefreshAsync(CancellationToken.None);
        Assert.Null(await catalog.FindByIdAsync("acme", CancellationToken.None));

        EnterTenant(provider, held);
        Assert.False(await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("taken"), "token-id")));
    }

    /// <summary>
    /// A store handing the former definition back in a reading the checks refuse leaves the tenant unserved, and a
    /// request still holding the former definition, answered with what was built from it, does not drop a client
    /// registered since under the id it configures.
    /// </summary>
    [Fact]
    public async Task RefusedRollback_KeepsRegistrationMadeSince()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var catalog = provider.GetRequiredService<StoreTenantCatalog>();
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith("freed"), "1");
        EnterTenant(provider, former);
        Assert.NotNull(await clients.TryFindClientAsync("freed"));
        var current = await Served(provider, store, AcmeWith(), "2");
        EnterTenant(provider, current);
        Assert.True(await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("freed"), "token-id")));

        // Globex claims acme's issuer, so the checks refuse both
        store.Tenants =
        [
            new StoredTenant(former, "3"),
            new StoredTenant(new TenantDefinition { Id = "globex", Issuer = AcmeIssuer }, "1"),
        ];
        await catalog.RefreshAsync(CancellationToken.None);
        Assert.Null(await catalog.FindByIdAsync("acme", CancellationToken.None));

        EnterTenant(provider, former);
        await clients.TryFindClientAsync("freed");

        EnterTenant(provider, current);
        Assert.NotNull(await manager.TryFindRegisteredClientAsync("freed"));
    }

    /// <summary>
    /// A tenant the store no longer holds answers a request holding its former definition with what was built from
    /// it, and drops no client registered since under the id that definition configures.
    /// </summary>
    [Fact]
    public async Task DroppedTenant_KeepsRegistrationMadeSince()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith("freed"), "1");
        EnterTenant(provider, former);
        Assert.NotNull(await clients.TryFindClientAsync("freed"));
        var current = await Served(provider, store, AcmeWith(), "2");
        EnterTenant(provider, current);
        Assert.True(await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("freed"), "token-id")));

        store.Tenants = [];
        await provider.GetRequiredService<StoreTenantCatalog>().RefreshAsync(CancellationToken.None);

        EnterTenant(provider, former);
        await clients.TryFindClientAsync("freed");

        EnterTenant(provider, current);
        Assert.NotNull(await manager.TryFindRegisteredClientAsync("freed"));
    }

    /// <summary>
    /// A tenant the store dropped after the clients of its last definition were built keeps that definition in
    /// force, so a request still holding the definition before, building its clients back, does not drop a client
    /// registered under an id only that earlier definition configures.
    /// </summary>
    [Fact]
    public async Task TenantDroppedAfterBuild_KeepsRegistrationMadeSince()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith("freed"), "1");
        EnterTenant(provider, former);
        Assert.NotNull(await clients.TryFindClientAsync("freed"));
        var current = await Served(provider, store, AcmeWith(), "2");
        EnterTenant(provider, current);
        Assert.Null(await clients.TryFindClientAsync("freed"));
        Assert.True(await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("freed"), "token-id")));

        store.Tenants = [];
        await provider.GetRequiredService<StoreTenantCatalog>().RefreshAsync(CancellationToken.None);

        EnterTenant(provider, former);
        await clients.TryFindClientAsync("freed");

        EnterTenant(provider, current);
        Assert.NotNull(await manager.TryFindRegisteredClientAsync("freed"));
    }

    /// <summary>
    /// Under a catalog of the host's own, a tenant the host hands a definition of its own is served the clients it
    /// declares, though the server's catalog, still reading the store, served another definition before.
    /// </summary>
    [Fact]
    public async Task HostCatalogDefinition_IsServedItsClients()
    {
        var store = new ChangingTenantStore { Tenants = [new StoredTenant(AcmeWith("stored"), "1")] };
        using var provider = ServingFrom(store, hostCatalog: true);
        await provider.GetRequiredService<StoreTenantCatalog>().RefreshAsync(CancellationToken.None);
        var catalog = provider.GetRequiredService<HostCatalog>();
        var clients = provider.GetRequiredService<IClientInfoProvider>();

        EnterTenant(provider, await catalog.FindByIdAsync("acme", CancellationToken.None));
        Assert.NotNull(await clients.TryFindClientAsync("stored"));

        catalog.Own = AcmeWith("own");
        EnterTenant(provider, await catalog.FindByIdAsync("acme", CancellationToken.None));
        Assert.NotNull(await clients.TryFindClientAsync("own"));
    }

    /// <summary>
    /// The default client store follows each tenant's definition under multi-tenancy, whichever of the two calls
    /// comes first, and reads a server's clients once without it, as before; the store finding clients is the one
    /// keeping them.
    /// </summary>
    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void DefaultClientStore_FollowsTenants_OnlyUnderMultiTenancy(bool multiTenancy, bool clientsFirst)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        if (clientsFirst)
            services.AddClientInformation();
        if (multiTenancy)
            services.AddServerStorage().AddMultiTenancy(_ => { });
        if (!clientsFirst)
            services.AddClientInformation();
        using var provider = services.BuildServiceProvider();

        var finding = provider.GetRequiredService<IClientInfoProvider>();
        Assert.Same(finding, provider.GetRequiredService<IClientInfoManager>());
        Assert.Equal(
            multiTenancy ? "ReloadableClientInfoStorage" : "ClientInfoStorage",
            finding.GetType().Name);
    }
}
