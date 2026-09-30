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
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// A registration access token manages the registration it was issued for and nothing else: once the settings
/// configure the id it was issued under, it manages nothing, however the registrant replays it, and whichever store
/// serves the clients.
/// </summary>
public class RegistrationManagementAcrossReloadTests
{
    private const string ClientId = TestConstants.DefaultClientId;

    private readonly Reloadable _options = new(new OidcOptions());
    private readonly OptionsIssuerSettings _settings;

    public RegistrationManagementAcrossReloadTests()
    {
        _settings = new OptionsIssuerSettings(_options);
    }

    private ReloadableClientInfoStorage ReloadableStore() => new(
        NullLogger<ReloadableClientInfoStorage>.Instance,
        _settings,
        new SingleIssuerLocal<Dictionary<string, ClientInfo>>(),
        new SingleIssuerLocal<ConcurrentDictionary<string, ClientInfo>>());

    private ClientInfoStorage DefaultStore()
        => new(_settings, new SingleIssuerLocal<ConcurrentDictionary<string, ClientInfo>>());

    private static Task RegisterAsync(IClientInfoManager clients, string tokenId)
        => clients.AddClientAsync(new ClientInfo(ClientId) { ClientName = "registered", RegistrationAccessTokenId = tokenId });

    private async Task<ValidClientRequest?> ManagesAsync(IClientInfoProvider clients, string tokenId)
    {
        var result = await new ClientRequestValidator(clients, new JtiMatches(), _settings).ValidateAsync(
            new ClientRequest
            {
                ClientId = ClientId,
                AuthorizationHeader = new AuthenticationHeaderValue(TokenTypes.Bearer, tokenId),
            });
        return result.TryGetSuccess(out var request) ? request : null;
    }

    private OidcOptions Configuring() => new()
    {
        Clients = [new ClientInfo(ClientId) { ClientName = "configured" }],
    };

    [Fact]
    public async Task ATokenOfARegistrationTheSettingsTakeOver_ManagesNothing()
    {
        var clients = ReloadableStore();
        await RegisterAsync(clients, "first");
        Assert.NotNull(await ManagesAsync(clients, "first"));

        _options.Reload(Configuring());

        Assert.Null(await ManagesAsync(clients, "first"));
        Assert.Equal("configured", (await clients.TryFindClientAsync(ClientId))?.ClientName);
    }

    [Fact]
    public async Task OnceTheSettingsLetTheIdGo_OnlyAFreshRegistrationManagesIt()
    {
        var clients = ReloadableStore();
        await RegisterAsync(clients, "first");
        _options.Reload(Configuring());
        Assert.Null(await ManagesAsync(clients, "first"));

        _options.Reload(new OidcOptions());
        Assert.Null(await clients.TryFindClientAsync(ClientId));
        Assert.Null(await ManagesAsync(clients, "first"));

        await RegisterAsync(clients, "second");
        Assert.NotNull(await ManagesAsync(clients, "second"));
        Assert.Null(await ManagesAsync(clients, "first"));
    }

    /// <summary>
    /// The default store does not follow a reload, so a registration it still serves stays its registrant's to
    /// manage when the settings come to configure its id; they take it over at the next start.
    /// </summary>
    [Fact]
    public async Task UnderTheDefaultStore_ARegistrationItStillServes_StaysManaged()
    {
        var clients = DefaultStore();
        await RegisterAsync(clients, "first");

        _options.Reload(Configuring());

        Assert.Equal("registered", (await ManagesAsync(clients, "first"))?.ClientInfo.ClientName);
    }

    /// <summary>
    /// The shape a restart leaves: the registration is gone with the memory that held it, the settings now configure
    /// its id, and the registrant still holds its token. The configured client carries no token id, so the token
    /// manages nothing - under the default store, and under the reloading one, which the settings reach on reload
    /// as well, whether the client was served before the reload or not.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ATokenOutlivingItsRegistration_ManagesNoConfiguredClient(bool defaultStore)
    {
        _options.Reload(Configuring());
        IClientInfoProvider clients = defaultStore ? DefaultStore() : ReloadableStore();

        Assert.Null(await ManagesAsync(clients, "left over"));

        _options.Reload(new OidcOptions { Clients = [new ClientInfo(ClientId) { ClientName = "changed" }] });
        Assert.Null(await ManagesAsync(clients, "left over"));
    }

    /// <summary>
    /// A store of the host's own, or a built-in one behind a host's decorator, reaches the same answer: the binding
    /// is on the client's record, so the endpoint needs to know nothing about the store to refuse.
    /// </summary>
    [Fact]
    public async Task BehindAHostsDecorator_AConfiguredClient_IsManagedByNoToken()
    {
        _options.Reload(Configuring());
        var clients = new Decorated(DefaultStore());

        Assert.Null(await ManagesAsync(clients, "left over"));

        _options.Reload(new OidcOptions());
        Assert.Null(await ManagesAsync(clients, "left over"));
    }

    private sealed class Reloadable(OidcOptions initial) : IOptionsMonitor<OidcOptions>
    {
        public OidcOptions CurrentValue { get; private set; } = initial;
        public void Reload(OidcOptions options) => CurrentValue = options;
        public OidcOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<OidcOptions, string?> listener) => null;
    }

    /// <summary>
    /// A host's decorator over a client store, which tells nothing of the store it wraps.
    /// </summary>
    private sealed class Decorated(IClientInfoProvider inner) : IClientInfoProvider
    {
        public Task<ClientInfo?> TryFindClientAsync(string clientId) => inner.TryFindClientAsync(clientId);
    }

    /// <summary>
    /// A token is the id it was issued under; it is valid while that is the id the client's record carries.
    /// </summary>
    private sealed class JtiMatches : IRegistrationAccessTokenValidator
    {
        public Task<string?> ValidateAsync(AuthenticationHeaderValue? header, string clientId, string expectedTokenId)
            => Task.FromResult(header?.Parameter == expectedTokenId ? null : "The access token unauthorized");
    }
}
