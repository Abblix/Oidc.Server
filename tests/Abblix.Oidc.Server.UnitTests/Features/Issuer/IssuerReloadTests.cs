// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
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
        var options = new ReloadableOptions(new TestIssuer { Resources = [new ResourceDefinition(Api)] });
        var resources = new ResourceManager(
            SingleIssuer.SettingsOf(options),
            SingleIssuer.LocalOf<Dictionary<Uri, ResourceDefinition>>(() => new TestIssuer()));
        Assert.False(resources.TryGet(Files, out _));

        options.Reload(new TestIssuer { Resources = [new ResourceDefinition(Api), new ResourceDefinition(Files)] });

        Assert.True(resources.TryGet(Files, out _));
    }

    [Fact]
    public void AScopeAReloadAdds_IsKnown()
    {
        var options = new ReloadableOptions(new TestIssuer());
        var scopes = new ScopeManager(
            SingleIssuer.SettingsOf(options),
            SingleIssuer.LocalOf<Dictionary<string, ScopeDefinition>>(() => new TestIssuer()));
        Assert.False(scopes.TryGet("files:read", out _));

        options.Reload(new TestIssuer { Scopes = [new ScopeDefinition("files:read")] });

        Assert.True(scopes.TryGet("files:read", out _));
    }

    [Fact]
    public async Task AReloadBringsTheClientsItConfigures_AndKeepsWhatRegistrationAdded()
    {
        var options = new ReloadableOptions(new TestIssuer { Clients = [new ClientInfo("configured")] });
        var clients = ClientsOf(options);
        Assert.True(await clients.TryAddClientAsync(Registration("registered")));

        options.Reload(new TestIssuer { Clients = [new ClientInfo("configured"), new ClientInfo("added")] });

        Assert.NotNull(await clients.TryFindClientAsync("added"));
        Assert.NotNull(await clients.TryFindClientAsync("configured"));
        Assert.NotNull(await clients.TryFindClientAsync("registered"));
    }

    [Fact]
    public async Task AClientAReloadDrops_IsNoLongerKnown()
    {
        var options = new ReloadableOptions(new TestIssuer { Clients = [new ClientInfo("configured")] });
        var clients = ClientsOf(options);
        Assert.NotNull(await clients.TryFindClientAsync("configured"));

        options.Reload(new TestIssuer());

        Assert.Null(await clients.TryFindClientAsync("configured"));
    }

    private static ReloadableClientInfoStorage ClientsOf(
        IOptionsMonitor<TestIssuer> options,
        ILogger<ReloadableClientInfoStorage>? logger = null) => new(
        logger ?? NullLogger<ReloadableClientInfoStorage>.Instance,
        SingleIssuer.SettingsOf(options),
        SingleIssuer.LocalOf<Dictionary<string, ClientInfo>>(() => options.CurrentValue),
        new IssuerClientRegistrations(
            SingleIssuer.LocalOf<ConcurrentDictionary<string, RegisteredClient>>(() => options.CurrentValue)));

    /// <summary>
    /// Clients the settings configure, whose reading, once armed, stops until the test lets it go on: it holds the
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
    /// A build of the clients a former reload configured, begun before the next reload and ending after, does not
    /// drop a registration made meanwhile under an id the next reload freed.
    /// </summary>
    [Fact]
    public async Task BuildOfFormerSettingsEndingLate_KeepsRegistrationMadeMeanwhile()
    {
        var held = new HeldClients(new ClientInfo("freed"));
        var options = new ReloadableOptions(new TestIssuer());
        var clients = ClientsOf(options);
        Assert.Null(await clients.TryFindClientAsync("other"));
        options.Reload(new TestIssuer { Clients = held });
        held.Armed = true;
        var building = Task.Run(() => clients.TryFindClientAsync("other"));
        Assert.True(await held.Reached.WaitAsync(HeldClients.Patience, TestContext.Current.CancellationToken));

        options.Reload(new TestIssuer());
        Assert.True(await clients.TryAddClientAsync(Registration("freed")));
        held.Released.Release();
        await building.WaitAsync(HeldClients.Patience, TestContext.Current.CancellationToken);

        Assert.NotNull(await clients.TryFindRegisteredClientAsync("freed"));
    }

    private static RegisteredClient Registration(string clientId, string? name = null, string tokenId = "jti-1")
        => new(new ClientInfo(clientId) { ClientName = name }, tokenId);

    /// <summary>
    /// A client registered under an id the settings later configure gives way to the configured one: otherwise a
    /// registrant choosing an id ahead of the administrator would be served in the configured client's place.
    /// </summary>
    [Fact]
    public async Task ARegistrationUnderAnIdAReloadConfigures_GivesWayToTheConfiguredClient()
    {
        var options = new ReloadableOptions(new TestIssuer());
        var clients = ClientsOf(options);
        Assert.True(await clients.TryAddClientAsync(Registration("partner-app", "registered")));

        options.Reload(new TestIssuer { Clients = [new ClientInfo("partner-app") { ClientName = "configured" }] });

        Assert.Equal("configured", (await clients.TryFindClientAsync("partner-app"))?.ClientName);
    }

    /// <summary>
    /// A registration under an id a reload configures is dropped rather than hidden, so it does not come back once
    /// the settings let the id go.
    /// </summary>
    [Fact]
    public async Task ARegistrationUnderAnIdAReloadConfigures_IsDropped()
    {
        var options = new ReloadableOptions(new TestIssuer());
        var clients = ClientsOf(options);
        Assert.True(await clients.TryAddClientAsync(Registration("partner-app", "registered")));
        options.Reload(new TestIssuer { Clients = [new ClientInfo("partner-app") { ClientName = "configured" }] });
        Assert.Equal("configured", (await clients.TryFindClientAsync("partner-app"))?.ClientName);

        options.Reload(new TestIssuer());

        Assert.Null(await clients.TryFindClientAsync("partner-app"));
    }

    [Fact]
    public async Task ARegistrationAReloadDrops_IsLogged()
    {
        var logger = new CapturingLogger<ReloadableClientInfoStorage>();
        var options = new ReloadableOptions(new TestIssuer());
        var clients = ClientsOf(options, logger);
        Assert.True(await clients.TryAddClientAsync(Registration("partner-app")));

        options.Reload(new TestIssuer { Clients = [new ClientInfo("partner-app")] });
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
        var options = new ReloadableOptions(new TestIssuer
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

        options.Reload(new TestIssuer());
        Assert.Null(await clients.TryFindClientAsync("partner-app"));
    }

    /// <summary>
    /// An update landing once the settings configure the id of the registration it was decided on is not made, and
    /// says so: the registration it would replace is gone with the reload.
    /// </summary>
    [Fact]
    public async Task AnUpdateUnderAnIdAReloadConfigured_IsNotMade()
    {
        var options = new ReloadableOptions(new TestIssuer());
        var clients = ClientsOf(options);
        var registration = Registration("partner-app", "registered");
        Assert.True(await clients.TryAddClientAsync(registration));
        options.Reload(new TestIssuer
        {
            Clients = [new ClientInfo("partner-app") { ClientName = "configured" }],
        });

        Assert.False(await clients.TryUpdateClientAsync(registration, Registration("partner-app", "updated", "jti-2")));
        Assert.Equal("configured", (await clients.TryFindClientAsync("partner-app"))?.ClientName);

        options.Reload(new TestIssuer());
        Assert.Null(await clients.TryFindClientAsync("partner-app"));
    }

    /// <summary>
    /// The settings own the ids they configure, so the store changes nothing under one.
    /// </summary>
    [Fact]
    public async Task AConfiguredClient_IsNeitherAddedOverNorChangedNorRemoved()
    {
        var options = new ReloadableOptions(new TestIssuer
        {
            Clients = [new ClientInfo("app") { ClientName = "configured" }],
        });
        var clients = ClientsOf(options);

        Assert.False(await clients.TryAddClientAsync(Registration("app", "added")));

        Assert.Null(await clients.TryFindRegisteredClientAsync("app"));
        Assert.False(await clients.TryUpdateClientAsync(Registration("app"), Registration("app", "updated", "jti-2")));
        Assert.False(await clients.TryRemoveClientAsync(Registration("app")));
        Assert.Equal("configured", (await ((IClientInfoProvider)clients).TryFindClientAsync("app"))?.ClientName);
    }

    [Fact]
    public async Task ARegistrationAfterAConfiguredClientLeaves_IsKept()
    {
        var options = new ReloadableOptions(new TestIssuer { Clients = [new ClientInfo("app")] });
        var clients = ClientsOf(options);
        Assert.NotNull(await clients.TryFindClientAsync("app"));
        options.Reload(new TestIssuer());

        Assert.True(await clients.TryAddClientAsync(Registration("app", "registered")));

        Assert.Equal("registered", (await clients.TryFindClientAsync("app"))?.ClientName);
    }

    [Fact]
    public async Task ARemovedRegistration_IsNoLongerKnown()
    {
        var clients = ClientsOf(new ReloadableOptions(new TestIssuer()));
        Assert.True(await clients.TryAddClientAsync(Registration("app")));

        Assert.True(await clients.TryRemoveClientAsync(Registration("app")));

        Assert.Null(await clients.TryFindRegisteredClientAsync("app"));
    }

    /// <summary>
    /// A change or removal decided on a registration since rotated changes nothing: of two updates decided on one
    /// registration only the first lands, and an update or removal racing another comes too late to undo it.
    /// </summary>
    [Fact]
    public async Task AChangeDecidedOnARotatedRegistration_ChangesNothing()
    {
        var clients = ClientsOf(new ReloadableOptions(new TestIssuer()));
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
    [Fact]
    public async Task AnUpdateAfterARemoval_DoesNotBringTheClientBack()
    {
        var clients = ClientsOf(new ReloadableOptions(new TestIssuer()));
        var registration = Registration("app");
        Assert.True(await clients.TryAddClientAsync(registration));
        Assert.True(await clients.TryRemoveClientAsync(registration));

        Assert.False(await clients.TryUpdateClientAsync(registration, Registration("app", "updated", "jti-2")));
        Assert.Null(await clients.TryFindRegisteredClientAsync("app"));
    }

    [Fact]
    public async Task TwoRegistrationsUnderOneId_KeepTheFirst()
    {
        var clients = ClientsOf(new ReloadableOptions(new TestIssuer()));

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
        var options = new ReloadableOptions(new TestIssuer());
        var clients = ClientsOf(options);
        Assert.True(await clients.TryAddClientAsync(Registration("app")));
        await clients.TryRemoveClientAsync(Registration("app"));

        options.Reload(new TestIssuer { Clients = [new ClientInfo("app")] });

        Assert.NotNull(await clients.TryFindClientAsync("app"));
    }

    /// <summary>
    /// Options a test replaces, as a configuration reload does.
    /// </summary>
    private sealed class ReloadableOptions(TestIssuer initial) : IOptionsMonitor<TestIssuer>
    {
        public TestIssuer CurrentValue { get; private set; } = initial;

        public void Reload(TestIssuer options) => CurrentValue = options;

        public TestIssuer Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<TestIssuer, string?> listener) => null;
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
