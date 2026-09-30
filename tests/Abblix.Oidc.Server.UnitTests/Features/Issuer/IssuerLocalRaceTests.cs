// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Xunit;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Features.Issuer;

/// <summary>
/// Two callers building an issuer's value at once get the same one, so what one of them writes into it - a client
/// registered on one request - is not lost in a value only the other holds.
/// </summary>
public class IssuerLocalRaceTests
{
    [Fact]
    public Task WithoutTenants_TwoFirstCallers_ShareOneValue() => BothShareOneValueAsync(new SingleIssuerLocal<object>());

    [Fact]
    public Task UnderATenant_TwoFirstCallers_ShareOneValue()
        => BothShareOneValueAsync(new TenantIssuerLocal<object>(new OneTenant()));

    private static async Task BothShareOneValueAsync(IIssuerLocal<object> local)
    {
        // Both callers are held inside the build until each has started one, so each has seen no value yet
        using var bothBuilding = new Barrier(2);
        object Build()
        {
            bothBuilding.SignalAndWait(TimeSpan.FromSeconds(10));
            return new object();
        }

        var first = Task.Run(() => local.GetOrCreate(null, Build));
        var second = Task.Run(() => local.GetOrCreate(null, Build));

        Assert.Same(await first, await second);
        Assert.Same(await first, local.GetOrCreate(null, () => new object()));
    }

    private sealed class OneTenant : ITenantAccessor
    {
        public TenantContext? Current { get; } = new()
        {
            Tenant = new TenantDefinition { Id = "acme", Issuer = "https://auth.example.com/tenants/acme" },
        };
    }
}
