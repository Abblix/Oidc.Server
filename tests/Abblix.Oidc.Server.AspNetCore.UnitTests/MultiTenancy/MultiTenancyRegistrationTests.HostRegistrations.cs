// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <remarks>
/// A host keeping the registrations of dynamic client registration in a store of its own, told the tenant of each
/// call.
/// </remarks>
public partial class MultiTenancyRegistrationTests
{
    private const string GlobexIssuer = "https://auth.example.com/tenants/globex";

    private static ServiceProvider ServingWithHostRegistrations(HostRegistrations registrations)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddClientInformation();
        services.AddSingleton<ITenantClientRegistrationStore>(registrations);
        services.AddServerStorage().AddMultiTenancy(_ => { });
        return services.BuildServiceProvider();
    }

    private static TenantDefinition Tenant(string id, string generation, params string[] configured) => new()
    {
        Id = id,
        Issuer = id == "acme" ? AcmeIssuer : GlobexIssuer,
        Generation = generation,
        Clients = [..configured.Select(clientId => new ClientInfo(clientId) { ClientName = "configured" })],
    };

    private static RegisteredClient Registration(string clientId) => new(new ClientInfo(clientId), "jti");

    /// <summary>
    /// A registration made at one tenant goes to the host's store under that tenant, is found there, and is not
    /// found at another tenant.
    /// </summary>
    [Fact]
    public async Task ARegistration_IsKeptInTheHostsStoreUnderItsTenant_AndUnknownToAnother()
    {
        var registrations = new HostRegistrations();
        using var provider = ServingWithHostRegistrations(registrations);
        var manager = provider.GetRequiredService<IClientInfoManager>();
        var clients = provider.GetRequiredService<IClientInfoProvider>();

        EnterTenant(provider, Tenant("acme", "1"));
        Assert.True(await manager.TryAddClientAsync(Registration("app")));
        Assert.Equal(("acme", "1", "APP"), Assert.Single(registrations.Held.Keys));
        Assert.NotNull(await clients.TryFindClientAsync("app"));

        EnterTenant(provider, Tenant("globex", "1"));
        Assert.Null(await clients.TryFindClientAsync("app"));
        Assert.Null(await manager.TryFindRegisteredClientAsync("app"));
    }

    /// <summary>
    /// A tenant created again under an id finds none of the registrations made at the creation before it.
    /// </summary>
    [Fact]
    public async Task ATenantCreatedAgain_FindsNoneOfTheEarlierCreationsRegistrations()
    {
        var registrations = new HostRegistrations();
        using var provider = ServingWithHostRegistrations(registrations);
        var clients = provider.GetRequiredService<IClientInfoProvider>();

        EnterTenant(provider, Tenant("acme", "1"));
        Assert.True(await provider.GetRequiredService<IClientInfoManager>().TryAddClientAsync(Registration("app")));

        EnterTenant(provider, Tenant("acme", "2"));
        Assert.Null(await clients.TryFindClientAsync("app"));
    }

    /// <summary>
    /// The definition's client is served over a registration under its id, which stays in the host's store until a
    /// request meets it, and is then removed and not found.
    /// </summary>
    [Fact]
    public async Task AConfiguredClient_IsServedOverARegistration_WhichIsRemovedFromTheHostsStoreWhenMet()
    {
        var registrations = new HostRegistrations();
        using var provider = ServingWithHostRegistrations(registrations);
        var manager = provider.GetRequiredService<IClientInfoManager>();
        EnterTenant(provider, Tenant("acme", "1"));
        Assert.True(await manager.TryAddClientAsync(Registration("app")));

        EnterTenant(provider, Tenant("acme", "1", "app"));
        Assert.Equal(
            "configured",
            (await provider.GetRequiredService<IClientInfoProvider>().TryFindClientAsync("app"))?.ClientName);
        Assert.Single(registrations.Held);

        Assert.Null(await manager.TryFindRegisteredClientAsync("app"));
        Assert.Empty(registrations.Held);
    }

    /// <summary>
    /// A call to the host's store that never returns holds up no configured client: a configured client is served
    /// without asking the store.
    /// </summary>
    [Fact]
    public async Task AHostsStoreThatHangs_HoldsUpNoConfiguredClient()
    {
        var registrations = new HostRegistrations { Hanging = true };
        using var provider = ServingWithHostRegistrations(registrations);
        EnterTenant(provider, Tenant("acme", "1", "app"));

        var found = await provider.GetRequiredService<IClientInfoProvider>()
            .TryFindClientAsync("app")
            .WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);

        Assert.NotNull(found);
    }

    /// <summary>
    /// A registration is changed and removed in the host's store, under its tenant.
    /// </summary>
    [Fact]
    public async Task ARegistration_IsChangedAndRemovedInTheHostsStore()
    {
        var registrations = new HostRegistrations();
        using var provider = ServingWithHostRegistrations(registrations);
        var manager = provider.GetRequiredService<IClientInfoManager>();
        EnterTenant(provider, Tenant("acme", "1"));
        var registered = Registration("app");
        Assert.True(await manager.TryAddClientAsync(registered));

        var updated = new RegisteredClient(new ClientInfo("app") { ClientName = "renamed" }, "jti-2");
        Assert.True(await manager.TryUpdateClientAsync(registered, updated));
        Assert.Equal("renamed", Assert.Single(registrations.Held.Values).ClientInfo.ClientName);

        Assert.True(await manager.TryRemoveClientAsync(updated));
        Assert.Empty(registrations.Held);
    }

    /// <summary>
    /// The settings own the ids they configure, so an addition under one is answered as not made and not kept in the
    /// host's store.
    /// </summary>
    [Fact]
    public async Task ARegistrationUnderAConfiguredId_IsNotKeptInTheHostsStore()
    {
        var registrations = new HostRegistrations();
        using var provider = ServingWithHostRegistrations(registrations);
        EnterTenant(provider, Tenant("acme", "1", "app"));

        Assert.False(await provider.GetRequiredService<IClientInfoManager>().TryAddClientAsync(Registration("app")));

        Assert.Empty(registrations.Held);
    }
}
