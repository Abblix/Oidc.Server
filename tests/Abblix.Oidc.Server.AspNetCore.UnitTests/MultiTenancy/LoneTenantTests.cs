// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// The one tenant of the options is served without <c>UseMultiTenancy()</c> only while it is one and at the root of
/// its host: several tenants need the call even when each is at the root of a host of its own, since each request is
/// matched to one by its address.
/// </summary>
public class LoneTenantTests
{
    [Theory]
    [InlineData(true, "https://auth.example.com")]
    [InlineData(false, "https://auth.example.com/tenants/acme")]
    [InlineData(false, "https://auth.example.com", "https://login.example.com")]
    public void TheCallIsNeeded_UnlessOneTenantIsAtTheRoot(bool servedWithoutTheCall, params string[] issuers)
    {
        using var services = new ServiceCollection()
            .AddServerStorage()
            .ServeTenants(options => options.Tenants.AddRange(issuers.Select((issuer, index) => new TenantDefinition
            {
                Id = $"tenant{index}",
                Issuer = new Uri(issuer),
            })))
            .BuildServiceProvider();

        var lone = services.GetRequiredService<LoneTenant>();

        Assert.Equal(servedWithoutTheCall, lone.WhyTheCallIsNeeded is null);
    }
}
