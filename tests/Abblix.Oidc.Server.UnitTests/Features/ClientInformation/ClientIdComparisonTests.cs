// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// A request names a client by its id exactly, while no tenant holds two clients under ids that differ only in case.
/// </summary>
public class ClientIdComparisonTests
{
    private static ReloadableClientInfoStorage Store() => new(
        NullLogger<ReloadableClientInfoStorage>.Instance,
        SingleIssuer.Catalog,
        SingleIssuer.LocalOf<Dictionary<string, ClientInfo>>(),
        new IssuerClientRegistrations(SingleIssuer.LocalOf<ConcurrentDictionary<string, RegisteredClient>>()));

    private static TenantDefinition Configuring(params string[] clientIds)
        => new TestIssuer { Clients = [..clientIds.Select(id => new ClientInfo(id))] }.ToTenant();

    private static RegisteredClient Registration(string clientId) => new(new ClientInfo(clientId), "jti");

    [Fact]
    public async Task ARegistration_IsFoundOnlyUnderItsExactId()
    {
        var store = Store();
        var tenant = Configuring();
        Assert.True(await store.TryAddClientAsync(tenant, Registration("abc")));

        Assert.Equal(ClientAbsence.Unknown, (await store.FindClientAsync(tenant, "ABC")).GetFailure());
        Assert.Null(await store.TryFindRegisteredClientAsync(tenant, "ABC"));
        Assert.Equal("abc", (await store.FindClientAsync(tenant, "abc")).GetSuccess().ClientId);
        Assert.Equal("abc", (await store.TryFindRegisteredClientAsync(tenant, "abc"))?.ClientInfo.ClientId);
    }

    [Fact]
    public async Task AnIdDifferingOnlyInCase_IsNotRegisteredBesideARegistration()
    {
        var store = Store();
        var tenant = Configuring();
        Assert.True(await store.TryAddClientAsync(tenant, Registration("abc")));

        Assert.False(await store.TryAddClientAsync(tenant, Registration("ABC")));
        Assert.Equal(ClientAbsence.Unknown, (await store.FindClientAsync(tenant, "ABC")).GetFailure());
    }

    [Fact]
    public async Task AConfiguredClient_IsFoundOnlyUnderItsExactId()
    {
        var store = Store();
        var tenant = Configuring("app");

        Assert.Equal(ClientAbsence.Unknown, (await store.FindClientAsync(tenant, "APP")).GetFailure());
        Assert.Equal("app", (await store.FindClientAsync(tenant, "app")).GetSuccess().ClientId);
    }

    [Fact]
    public async Task AnIdDifferingOnlyInCase_IsNotRegisteredBesideAConfiguredClient()
    {
        var store = Store();
        var tenant = Configuring("app");

        Assert.False(await store.TryAddClientAsync(tenant, Registration("APP")));
        Assert.Equal(ClientAbsence.Unknown, (await store.FindClientAsync(tenant, "APP")).GetFailure());
    }

    /// <summary>
    /// The settings coming to configure an id drop a registration held under it in another case, as the store first
    /// builds the clients they configure.
    /// </summary>
    [Fact]
    public async Task ARegistrationUnderAnIdTheSettingsComeToConfigureInAnotherCase_IsDropped()
    {
        var store = Store();
        var before = Configuring();
        Assert.True(await store.TryAddClientAsync(before, Registration("APP")));

        Assert.Equal("app", (await store.FindClientAsync(Configuring("app"), "app")).GetSuccess().ClientId);

        Assert.Null(await store.TryFindRegisteredClientAsync(before, "APP"));
    }
}
