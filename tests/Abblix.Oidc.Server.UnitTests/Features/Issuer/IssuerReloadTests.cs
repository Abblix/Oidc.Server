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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Issuer;

/// <summary>
/// What is built once from the issuer's settings - its clients, scopes and resources - is built again when a reload
/// brings other settings, so it never disagrees with the settings read beside it.
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
        var clients = new ClientInfoStorage(
            new OptionsIssuerSettings(options),
            new SingleIssuerLocal<ConcurrentDictionary<string, ClientInfo>>(),
            new SingleIssuerLocal<ConcurrentDictionary<string, ClientInfo?>>());
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
        var clients = new ClientInfoStorage(
            new OptionsIssuerSettings(options),
            new SingleIssuerLocal<ConcurrentDictionary<string, ClientInfo>>(),
            new SingleIssuerLocal<ConcurrentDictionary<string, ClientInfo?>>());
        Assert.NotNull(await clients.TryFindClientAsync("configured"));

        options.Reload(new OidcOptions());

        Assert.Null(await clients.TryFindClientAsync("configured"));
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
