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
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Issuer;

/// <summary>
/// What is built from the issuer's settings - its scopes and resources, and its clients in the reloading store - is
/// built again when a reload brings other settings, so it never disagrees with the settings read beside it. The
/// default client store keeps the clients it started with.
/// </summary>
public class IssuerReloadTests
{
    private static readonly Uri Api = new("https://api.example.com");
    private static readonly Uri Files = new("https://files.example.com");

    [Fact]
    public void AResourceAReloadAdds_IsKnown()
    {
        var options = new ReloadableOptions(new OidcOptions { Resources = [new ResourceDefinition(Api)] });
        var resources = new ResourceManager(
            new OptionsIssuerSettings(options),
            new SingleIssuerLocal<Dictionary<Uri, ResourceDefinition>>());
        Assert.False(resources.TryGet(Files, out _));

        options.Reload(new OidcOptions { Resources = [new ResourceDefinition(Api), new ResourceDefinition(Files)] });

        Assert.True(resources.TryGet(Files, out _));
    }

    [Fact]
    public void AScopeAReloadAdds_IsKnown()
    {
        var options = new ReloadableOptions(new OidcOptions());
        var scopes = new ScopeManager(
            new OptionsIssuerSettings(options),
            new SingleIssuerLocal<Dictionary<string, ScopeDefinition>>());
        Assert.False(scopes.TryGet("files:read", out _));

        options.Reload(new OidcOptions { Scopes = [new ScopeDefinition("files:read")] });

        Assert.True(scopes.TryGet("files:read", out _));
    }

    [Fact]
    public async Task AReloadBringsTheClientsItConfigures_AndKeepsWhatRegistrationChanged()
    {
        var options = new ReloadableOptions(new OidcOptions
        {
            Clients = [new ClientInfo("configured"), new ClientInfo("retired")],
        });
        var clients = ClientsOf(options);
        await clients.AddClientAsync(new ClientInfo("registered"));
        await clients.RemoveClientAsync("retired");

        options.Reload(new OidcOptions
        {
            Clients = [new ClientInfo("configured"), new ClientInfo("retired"), new ClientInfo("added")],
        });

        Assert.NotNull(await clients.TryFindClientAsync("added"));
        Assert.NotNull(await clients.TryFindClientAsync("configured"));
        Assert.NotNull(await clients.TryFindClientAsync("registered"));
        Assert.Null(await clients.TryFindClientAsync("retired"));
    }

    [Fact]
    public async Task AClientAReloadDrops_IsNoLongerKnown()
    {
        var options = new ReloadableOptions(new OidcOptions { Clients = [new ClientInfo("configured")] });
        var clients = ClientsOf(options);
        Assert.NotNull(await clients.TryFindClientAsync("configured"));

        options.Reload(new OidcOptions());

        Assert.Null(await clients.TryFindClientAsync("configured"));
    }

    private static ReloadableClientInfoStorage ClientsOf(IOptionsMonitor<OidcOptions> options) => new(
        NullLogger<ReloadableClientInfoStorage>.Instance,
        new OptionsIssuerSettings(options),
        new SingleIssuerLocal<ConcurrentDictionary<string, ClientInfo>>(),
        new SingleIssuerLocal<ConcurrentDictionary<string, ReloadableClientInfoStorage.Registration>>());

    /// <summary>
    /// A client registered under an id the settings later configure gives way to the configured one: otherwise a
    /// registrant choosing an id ahead of the administrator would be served in the configured client's place.
    /// </summary>
    [Fact]
    public async Task ARegistrationUnderAnIdAReloadConfigures_GivesWayToTheConfiguredClient()
    {
        var options = new ReloadableOptions(new OidcOptions());
        var clients = ClientsOf(options);
        await clients.AddClientAsync(new ClientInfo("partner-app") { ClientName = "registered" });

        options.Reload(new OidcOptions { Clients = [new ClientInfo("partner-app") { ClientName = "configured" }] });

        Assert.Equal("configured", (await clients.TryFindClientAsync("partner-app"))?.ClientName);
    }

    /// <summary>
    /// A registration under an id a reload configures is dropped rather than hidden, so it does not come back once
    /// the settings let the id go.
    /// </summary>
    [Fact]
    public async Task ARegistrationUnderAnIdAReloadConfigures_IsDropped()
    {
        var options = new ReloadableOptions(new OidcOptions());
        var clients = ClientsOf(options);
        await clients.AddClientAsync(new ClientInfo("partner-app") { ClientName = "registered" });
        options.Reload(new OidcOptions { Clients = [new ClientInfo("partner-app") { ClientName = "configured" }] });
        Assert.Equal("configured", (await clients.TryFindClientAsync("partner-app"))?.ClientName);

        options.Reload(new OidcOptions());

        Assert.Null(await clients.TryFindClientAsync("partner-app"));
    }

    /// <summary>
    /// A configured client's removal, remembered while the settings configure it, does not refuse a client registered
    /// under its id once they no longer do.
    /// </summary>
    [Fact]
    public async Task ARegistrationAfterAConfiguredClientLeaves_IsKept()
    {
        var options = new ReloadableOptions(new OidcOptions { Clients = [new ClientInfo("app")] });
        var clients = ClientsOf(options);
        await clients.RemoveClientAsync("app");
        options.Reload(new OidcOptions());

        await clients.AddClientAsync(new ClientInfo("app") { ClientName = "registered" });

        Assert.Equal("registered", (await clients.TryFindClientAsync("app"))?.ClientName);
    }

    [Fact]
    public async Task AnUpdateOfAConfiguredClient_OutlivesAReload()
    {
        var options = new ReloadableOptions(new OidcOptions { Clients = [new ClientInfo("configured")] });
        var clients = ClientsOf(options);
        await clients.UpdateClientAsync(new ClientInfo("configured") { ClientName = "updated" });

        options.Reload(new OidcOptions { Clients = [new ClientInfo("configured"), new ClientInfo("added")] });

        Assert.Equal("updated", (await clients.TryFindClientAsync("configured"))?.ClientName);
    }

    [Fact]
    public async Task TwoRegistrationsUnderOneId_KeepTheFirst()
    {
        var clients = ClientsOf(new ReloadableOptions(new OidcOptions()));

        await clients.AddClientAsync(new ClientInfo("app") { ClientName = "first" });
        await clients.AddClientAsync(new ClientInfo("app") { ClientName = "second" });

        Assert.Equal("first", (await clients.TryFindClientAsync("app"))?.ClientName);
    }

    /// <summary>
    /// Removing a client registration made no removal of a configured client, so it leaves nothing behind to hide a
    /// client of that id the settings configure later.
    /// </summary>
    [Fact]
    public async Task ARemovedRegistration_HidesNoClientAReloadConfigures()
    {
        var options = new ReloadableOptions(new OidcOptions());
        var clients = ClientsOf(options);
        await clients.AddClientAsync(new ClientInfo("app"));
        await clients.RemoveClientAsync("app");

        options.Reload(new OidcOptions { Clients = [new ClientInfo("app")] });

        Assert.NotNull(await clients.TryFindClientAsync("app"));
    }

    /// <summary>
    /// The default store reads the configured clients once, so a reload does not reach them.
    /// </summary>
    [Fact]
    public async Task TheDefaultStore_KeepsTheClientsItStartedWith()
    {
        var options = new ReloadableOptions(new OidcOptions { Clients = [new ClientInfo("configured")] });
        var clients = new ClientInfoStorage(
            new OptionsIssuerSettings(options),
            new SingleIssuerLocal<ConcurrentDictionary<string, ClientInfo>>());
        Assert.NotNull(await clients.TryFindClientAsync("configured"));

        options.Reload(new OidcOptions { Clients = [new ClientInfo("added")] });

        Assert.NotNull(await clients.TryFindClientAsync("configured"));
        Assert.Null(await clients.TryFindClientAsync("added"));
    }

    /// <summary>
    /// The reloadable store serves both the lookups and the registrations, whether it is asked for before or after
    /// the server's own registrations.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TheReloadableStore_ServesClientsWhereverItIsAskedFor(bool beforeTheServer)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        if (beforeTheServer)
            services.AddReloadableClientInformation();
        services.AddClientInformation();
        if (!beforeTheServer)
            services.AddReloadableClientInformation();

        // The startup checks of the options take services this test has no use for
        services.RemoveAll<IValidateOptions<OidcOptions>>();
        using var provider = services.BuildServiceProvider();

        var clients = Assert.IsType<ReloadableClientInfoStorage>(provider.GetRequiredService<IClientInfoProvider>());
        Assert.Same(clients, provider.GetRequiredService<IClientInfoManager>());
    }

    /// <summary>
    /// Options a test replaces, as a configuration reload does.
    /// </summary>
    private sealed class ReloadableOptions(OidcOptions initial) : IOptionsMonitor<OidcOptions>
    {
        public OidcOptions CurrentValue { get; private set; } = initial;

        public void Reload(OidcOptions options) => CurrentValue = options;

        public OidcOptions Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<OidcOptions, string?> listener) => null;
    }
}
