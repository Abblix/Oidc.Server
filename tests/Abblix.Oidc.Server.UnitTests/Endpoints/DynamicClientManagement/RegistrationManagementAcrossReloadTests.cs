// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Concurrent;
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
/// configure the id it was issued under, it manages nothing, however the registrant replays it.
/// </summary>
public class RegistrationManagementAcrossReloadTests
{
    private const string ClientId = TestConstants.DefaultClientId;

    private readonly Reloadable _options = new(new OidcOptions());
    private readonly ReloadableClientInfoStorage _clients;
    private readonly ClientRequestValidator _management;
    private readonly Bindings _bindings = new();

    public RegistrationManagementAcrossReloadTests()
    {
        var settings = new OptionsIssuerSettings(_options);
        _clients = new ReloadableClientInfoStorage(
            NullLogger<ReloadableClientInfoStorage>.Instance,
            settings,
            new SingleIssuerLocal<ConcurrentDictionary<string, ClientInfo>>(),
            new SingleIssuerLocal<ConcurrentDictionary<string, ReloadableClientInfoStorage.Registration>>());
        _management = new ClientRequestValidator(_clients, new JtiMatches(), _bindings, settings);
    }

    private async Task RegisterAsync(string tokenId)
    {
        await _clients.AddClientAsync(new ClientInfo(ClientId) { ClientName = "registered" });
        await _bindings.SetTokenIdAsync(ClientId, tokenId);
    }

    private async Task<bool> ManagesAsync(string tokenId)
        => (await _management.ValidateAsync(new ClientRequest
        {
            ClientId = ClientId,
            AuthorizationHeader = new AuthenticationHeaderValue(TokenTypes.Bearer, tokenId),
        })).TryGetSuccess(out _);

    private OidcOptions Configuring() => new()
    {
        Clients = [new ClientInfo(ClientId) { ClientName = "configured" }],
    };

    [Fact]
    public async Task ATokenOfARegistrationTheSettingsTakeOver_ManagesNothing()
    {
        await RegisterAsync("first");
        Assert.True(await ManagesAsync("first"));

        _options.Reload(Configuring());

        Assert.False(await ManagesAsync("first"));
        Assert.Null(await _bindings.GetTokenIdAsync(ClientId));
        Assert.False(await ManagesAsync("first"));
        Assert.Equal("configured", (await _clients.TryFindClientAsync(ClientId))?.ClientName);
    }

    [Fact]
    public async Task OnceTheSettingsLetTheIdGo_OnlyAFreshRegistrationManagesIt()
    {
        await RegisterAsync("first");
        _options.Reload(Configuring());
        Assert.False(await ManagesAsync("first"));

        _options.Reload(new OidcOptions());
        Assert.Null(await _clients.TryFindClientAsync(ClientId));
        Assert.False(await ManagesAsync("first"));

        await RegisterAsync("second");
        Assert.True(await ManagesAsync("second"));
        Assert.False(await ManagesAsync("first"));
    }

    /// <summary>
    /// The shape the default store meets across a restart: the binding outlives the registration, and the settings
    /// meanwhile configure the id.
    /// </summary>
    [Fact]
    public async Task ABindingLeftForAnIdTheSettingsConfigure_IsRevoked()
    {
        _options.Reload(Configuring());
        await _bindings.SetTokenIdAsync(ClientId, "left over");

        Assert.False(await ManagesAsync("left over"));
        Assert.Null(await _bindings.GetTokenIdAsync(ClientId));
    }

    private sealed class Reloadable(OidcOptions initial) : IOptionsMonitor<OidcOptions>
    {
        public OidcOptions CurrentValue { get; private set; } = initial;
        public void Reload(OidcOptions options) => CurrentValue = options;
        public OidcOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<OidcOptions, string?> listener) => null;
    }

    /// <summary>
    /// A token is the id it was issued under; it is valid while that is the id the binding records.
    /// </summary>
    private sealed class JtiMatches : IRegistrationAccessTokenValidator
    {
        public Task<string?> ValidateAsync(AuthenticationHeaderValue? header, string clientId, string? expectedTokenId)
            => Task.FromResult(header?.Parameter == expectedTokenId ? null : "The access token unauthorized");
    }

    private sealed class Bindings : IRegistrationAccessTokenStore
    {
        private readonly ConcurrentDictionary<string, string> _tokenIds = new(StringComparer.Ordinal);

        public Task SetTokenIdAsync(string clientId, string tokenId)
        {
            _tokenIds[clientId] = tokenId;
            return Task.CompletedTask;
        }

        public Task<string?> GetTokenIdAsync(string clientId)
            => Task.FromResult(_tokenIds.TryGetValue(clientId, out var tokenId) ? tokenId : null);

        public Task RemoveAsync(string clientId)
        {
            _tokenIds.TryRemove(clientId, out _);
            return Task.CompletedTask;
        }
    }
}
