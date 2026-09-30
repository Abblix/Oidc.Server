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
using Microsoft.Extensions.Logging;
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
    public async Task AReloadBringsTheClientsItConfigures_AndKeepsWhatRegistrationAdded()
    {
        var options = new ReloadableOptions(new OidcOptions { Clients = [new ClientInfo("configured")] });
        var clients = ClientsOf(options);
        Assert.True(await clients.TryAddClientAsync(Registration("registered")));

        options.Reload(new OidcOptions { Clients = [new ClientInfo("configured"), new ClientInfo("added")] });

        Assert.NotNull(await clients.TryFindClientAsync("added"));
        Assert.NotNull(await clients.TryFindClientAsync("configured"));
        Assert.NotNull(await clients.TryFindClientAsync("registered"));
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

    private static ReloadableClientInfoStorage ClientsOf(
        IOptionsMonitor<OidcOptions> options,
        ILogger<ReloadableClientInfoStorage>? logger = null) => new(
        logger ?? NullLogger<ReloadableClientInfoStorage>.Instance,
        new OptionsIssuerSettings(options),
        new SingleIssuerLocal<Dictionary<string, ClientInfo>>(),
        new SingleIssuerLocal<ConcurrentDictionary<string, RegisteredClient>>());

    private static ClientInfoStorage DefaultClientsOf(IOptionsMonitor<OidcOptions> options) => new(
        new OptionsIssuerSettings(options),
        new SingleIssuerLocal<Dictionary<string, ClientInfo>>(),
        new SingleIssuerLocal<ConcurrentDictionary<string, RegisteredClient>>());

    private static IClientInfoManager StoreOf(bool reloadable, IOptionsMonitor<OidcOptions> options)
        => reloadable ? ClientsOf(options) : DefaultClientsOf(options);

    private static RegisteredClient Registration(string clientId, string? name = null, string tokenId = "jti-1")
        => new(new ClientInfo(clientId) { ClientName = name }, tokenId);

    /// <summary>
    /// A client registered under an id the settings later configure gives way to the configured one: otherwise a
    /// registrant choosing an id ahead of the administrator would be served in the configured client's place.
    /// </summary>
    [Fact]
    public async Task ARegistrationUnderAnIdAReloadConfigures_GivesWayToTheConfiguredClient()
    {
        var options = new ReloadableOptions(new OidcOptions());
        var clients = ClientsOf(options);
        Assert.True(await clients.TryAddClientAsync(Registration("partner-app", "registered")));

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
        Assert.True(await clients.TryAddClientAsync(Registration("partner-app", "registered")));
        options.Reload(new OidcOptions { Clients = [new ClientInfo("partner-app") { ClientName = "configured" }] });
        Assert.Equal("configured", (await clients.TryFindClientAsync("partner-app"))?.ClientName);

        options.Reload(new OidcOptions());

        Assert.Null(await clients.TryFindClientAsync("partner-app"));
    }

    [Fact]
    public async Task ARegistrationAReloadDrops_IsLogged()
    {
        var logger = new CapturingLogger<ReloadableClientInfoStorage>();
        var options = new ReloadableOptions(new OidcOptions());
        var clients = ClientsOf(options, logger);
        Assert.True(await clients.TryAddClientAsync(Registration("partner-app")));

        options.Reload(new OidcOptions { Clients = [new ClientInfo("partner-app")] });
        await clients.TryFindClientAsync("partner-app");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal(LogEvents.ClientInformation.ReloadableClientInfoStorage.RegistrationEvicted, entry.EventId.Id);
    }

    /// <summary>
    /// A client added under an id the settings configure - as when a registration decided under earlier settings
    /// lands after a reload that configures its id - is answered as not added and not kept: nothing would evict it
    /// later, and it would come back once the id leaves the settings.
    /// </summary>
    [Fact]
    public async Task AClientAddedUnderAConfiguredId_DoesNotComeBackWhenTheIdLeaves()
    {
        var options = new ReloadableOptions(new OidcOptions
        {
            Clients = [new ClientInfo("partner-app") { ClientName = "configured" }],
        });
        var logger = new CapturingLogger<ReloadableClientInfoStorage>();
        var clients = ClientsOf(options, logger);
        Assert.NotNull(await clients.TryFindClientAsync("partner-app"));

        Assert.False(await clients.TryAddClientAsync(Registration("partner-app", "registered")));
        Assert.Equal(
            LogEvents.ClientInformation.ReloadableClientInfoStorage.RegistrationEvicted,
            Assert.Single(logger.Entries).EventId.Id);
        Assert.Equal("configured", (await clients.TryFindClientAsync("partner-app"))?.ClientName);

        options.Reload(new OidcOptions());
        Assert.Null(await clients.TryFindClientAsync("partner-app"));
    }

    /// <summary>
    /// An update landing once the settings configure the id of the registration it was decided on is not made, and
    /// says so: the registration it would replace is gone with the reload.
    /// </summary>
    [Fact]
    public async Task AnUpdateUnderAnIdAReloadConfigured_IsNotMade()
    {
        var options = new ReloadableOptions(new OidcOptions());
        var clients = ClientsOf(options);
        var registration = Registration("partner-app", "registered");
        Assert.True(await clients.TryAddClientAsync(registration));
        options.Reload(new OidcOptions
        {
            Clients = [new ClientInfo("partner-app") { ClientName = "configured" }],
        });

        Assert.False(await clients.TryUpdateClientAsync(registration, Registration("partner-app", "updated", "jti-2")));
        Assert.Equal("configured", (await clients.TryFindClientAsync("partner-app"))?.ClientName);

        options.Reload(new OidcOptions());
        Assert.Null(await clients.TryFindClientAsync("partner-app"));
    }

    /// <summary>
    /// The settings own the ids they configure, so the store changes nothing under one.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AConfiguredClient_IsNeitherAddedOverNorChangedNorRemoved(bool reloadable)
    {
        var options = new ReloadableOptions(new OidcOptions
        {
            Clients = [new ClientInfo("app") { ClientName = "configured" }],
        });
        var clients = StoreOf(reloadable, options);

        Assert.False(await clients.TryAddClientAsync(Registration("app", "added")));

        Assert.Null(await clients.TryFindRegisteredClientAsync("app"));
        Assert.False(await clients.TryUpdateClientAsync(Registration("app"), Registration("app", "updated", "jti-2")));
        Assert.False(await clients.TryRemoveClientAsync(Registration("app")));
        Assert.Equal("configured", (await ((IClientInfoProvider)clients).TryFindClientAsync("app"))?.ClientName);
    }

    [Fact]
    public async Task ARegistrationAfterAConfiguredClientLeaves_IsKept()
    {
        var options = new ReloadableOptions(new OidcOptions { Clients = [new ClientInfo("app")] });
        var clients = ClientsOf(options);
        Assert.NotNull(await clients.TryFindClientAsync("app"));
        options.Reload(new OidcOptions());

        Assert.True(await clients.TryAddClientAsync(Registration("app", "registered")));

        Assert.Equal("registered", (await clients.TryFindClientAsync("app"))?.ClientName);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ARemovedRegistration_IsNoLongerKnown(bool reloadable)
    {
        var clients = StoreOf(reloadable, new ReloadableOptions(new OidcOptions()));
        Assert.True(await clients.TryAddClientAsync(Registration("app")));

        Assert.True(await clients.TryRemoveClientAsync(Registration("app")));

        Assert.Null(await clients.TryFindRegisteredClientAsync("app"));
    }

    /// <summary>
    /// A change or removal decided on a registration since rotated changes nothing: of two updates decided on one
    /// registration only the first lands, and an update or removal racing another comes too late to undo it.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AChangeDecidedOnARotatedRegistration_ChangesNothing(bool reloadable)
    {
        var clients = StoreOf(reloadable, new ReloadableOptions(new OidcOptions()));
        var first = Registration("app", "first");
        Assert.True(await clients.TryAddClientAsync(first));
        var second = Registration("app", "second", "jti-2");

        Assert.True(await clients.TryUpdateClientAsync(first, second));
        Assert.False(await clients.TryUpdateClientAsync(first, Registration("app", "late", "jti-3")));
        Assert.False(await clients.TryRemoveClientAsync(first));

        var held = await clients.TryFindRegisteredClientAsync("app");
        Assert.Equal("second", held?.ClientInfo.ClientName);
        Assert.Equal("jti-2", held?.RegistrationAccessTokenId);
    }

    /// <summary>
    /// An update landing after the removal it raced does not bring the client back.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AnUpdateAfterARemoval_DoesNotBringTheClientBack(bool reloadable)
    {
        var clients = StoreOf(reloadable, new ReloadableOptions(new OidcOptions()));
        var registration = Registration("app");
        Assert.True(await clients.TryAddClientAsync(registration));
        Assert.True(await clients.TryRemoveClientAsync(registration));

        Assert.False(await clients.TryUpdateClientAsync(registration, Registration("app", "updated", "jti-2")));
        Assert.Null(await clients.TryFindRegisteredClientAsync("app"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TwoRegistrationsUnderOneId_KeepTheFirst(bool reloadable)
    {
        var clients = StoreOf(reloadable, new ReloadableOptions(new OidcOptions()));

        Assert.True(await clients.TryAddClientAsync(Registration("app", "first")));
        Assert.False(await clients.TryAddClientAsync(Registration("app", "second")));

        Assert.Equal("first", (await clients.TryFindRegisteredClientAsync("app"))?.ClientInfo.ClientName);
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
        Assert.True(await clients.TryAddClientAsync(Registration("app")));
        await clients.TryRemoveClientAsync(Registration("app"));

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
        var clients = DefaultClientsOf(options);
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

    /// <summary>
    /// Records the level and event of each entry.
    /// </summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, EventId EventId)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, eventId));
    }
}
