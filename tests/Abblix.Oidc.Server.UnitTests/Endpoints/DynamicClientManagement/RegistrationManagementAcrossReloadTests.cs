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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// A registration access token manages the registration holding its jti and nothing else: a client the store
/// serves from the settings is held by no registration, so no token manages it, and a registration the store drops when
/// the settings come to configure its id takes its token's reach with it.
/// </summary>
public class RegistrationManagementAcrossReloadTests
{
    private const string ClientId = TestConstants.DefaultClientId;

    private readonly Reloadable _options = new(new TestIssuer());

    private static ReloadableClientInfoStorage ReloadableStore() => new(
        NullLogger<ReloadableClientInfoStorage>.Instance,
        SingleIssuer.Catalog,
        SingleIssuer.LocalOf<Dictionary<string, ClientInfo>>(),
        new IssuerClientRegistrations(
            SingleIssuer.LocalOf<ConcurrentDictionary<string, RegisteredClient>>()));

    private async Task RegisterAsync(IClientInfoManager clients, string tokenId)
        => Assert.True(await clients.TryAddClientAsync(
            _options.CurrentValue.ToTenant(),
            new RegisteredClient(new ClientInfo(ClientId) { ClientName = "registered" }, tokenId)));

    private async Task<ValidClientRequest?> ManagesAsync(IClientInfoManager clients, string tokenId)
    {
        var result = await new ClientRequestValidator(clients, new TokenIsItsJti()).ValidateAsync(
            _options.CurrentValue.ToTenant(),
            new ClientRequest
            {
                ClientId = ClientId,
                AuthorizationHeader = new AuthenticationHeaderValue(TokenTypes.Bearer, tokenId),
            });
        return result.TryGetSuccess(out var request) ? request : null;
    }

    private static TestIssuer Configuring() => new()
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
        Assert.Equal("configured", (await clients.TryFindClientAsync(_options.CurrentValue.ToTenant(), ClientId))?.ClientName);
    }

    [Fact]
    public async Task OnceTheSettingsLetTheIdGo_OnlyAFreshRegistrationManagesIt()
    {
        var clients = ReloadableStore();
        await RegisterAsync(clients, "first");
        _options.Reload(Configuring());
        Assert.Null(await ManagesAsync(clients, "first"));

        _options.Reload(new TestIssuer());
        Assert.Null(await clients.TryFindClientAsync(_options.CurrentValue.ToTenant(), ClientId));
        Assert.Null(await ManagesAsync(clients, "first"));

        await RegisterAsync(clients, "second");
        Assert.NotNull(await ManagesAsync(clients, "second"));
        Assert.Null(await ManagesAsync(clients, "first"));
    }

    /// <summary>
    /// The shape a restart leaves: the registration is gone with the memory that held it, the settings now configure
    /// its id, and the registrant still holds its token. No registration is held under the id, so the token manages
    /// nothing, before and after the settings change again.
    /// </summary>
    [Fact]
    public async Task ATokenOutlivingItsRegistration_ManagesNoConfiguredClient()
    {
        _options.Reload(Configuring());
        var clients = ReloadableStore();

        Assert.Null(await ManagesAsync(clients, "left over"));

        _options.Reload(new TestIssuer { Clients = [new ClientInfo(ClientId) { ClientName = "changed" }] });
        Assert.Null(await ManagesAsync(clients, "left over"));
    }

    private sealed class Reloadable(TestIssuer initial) : IOptionsMonitor<TestIssuer>
    {
        public TestIssuer CurrentValue { get; private set; } = initial;
        public void Reload(TestIssuer options) => CurrentValue = options;
        public TestIssuer Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<TestIssuer, string?> listener) => null;
    }

    /// <summary>
    /// A token is the jti it was issued under.
    /// </summary>
    private sealed class TokenIsItsJti : IRegistrationAccessTokenValidator
    {
        public Task<Result<string, OidcError>> ValidateAsync(TenantDefinition tenant, AuthenticationHeaderValue? header, string clientId)
            => Task.FromResult<Result<string, OidcError>>(header.NotNull(nameof(header)).Parameter.NotNull(nameof(header)));
    }
}
