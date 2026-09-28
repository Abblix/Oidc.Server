// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net;
using System.Threading.Tasks;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// A tenant named in the path reaches an endpoint of a web application wired the way a host wires one, without
/// a routing call of its own.
/// </summary>
/// <remarks>
/// A web application routes at the front of the pipeline unless the host places routing itself, which would
/// match the endpoint against the full path, tenant segments included, before resolution moves them into the
/// path base - and every path tenant would be answered 404. Only a running application shows that.
/// </remarks>
public class TenantRoutingTests
{
    [Fact]
    public async Task APathTenant_ReachesTheEndpoint_WithItsSegmentsInThePathBase()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddMultiTenancy(options => options.Tenants.Add(
            new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/t/globex" }));

        await using var app = builder.Build();
        app.UseMultiTenancy();
        app.MapGet("/connect/probe", (HttpContext context) =>
            $"{context.Request.PathBase}|{context.Features.Get<TenantContext>()?.Tenant.Id}");
        await app.StartAsync(TestContext.Current.CancellationToken);

        using var client = app.GetTestClient();
        var response = await client.GetAsync("/t/globex/connect/probe", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("/t/globex|globex", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Placed after the host's own routing, resolution would come too late - a route, a fallback page included,
    /// is already matched on the full path - so the call is refused where the pipeline is built.
    /// </summary>
    [Fact]
    public void UseMultiTenancy_AfterTheHostsOwnRouting_IsRefused()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddMultiTenancy(options => options.Tenants.Add(
            new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/t/globex" }));
        var app = builder.Build();
        app.UseRouting();

        var refusal = Assert.Throws<InvalidOperationException>(() => app.UseMultiTenancy());
        Assert.Contains("before UseRouting()", refusal.Message, StringComparison.Ordinal);
    }
}
