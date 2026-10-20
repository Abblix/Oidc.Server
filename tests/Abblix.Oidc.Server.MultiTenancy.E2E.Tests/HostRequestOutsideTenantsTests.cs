// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Abblix.Oidc.Server.Features.Consents;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A request of the host's own that is addressed to no tenant passes the tenant resolution untouched: the host sees
/// the path, the path base and the absence of a tenant it would see without the library.
/// </summary>
public sealed class HostRequestOutsideTenantsTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string EchoPath = "/host/echo";

    private WebApplication _plain = null!;
    private WebApplication _multiTenant = null!;

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        var plain = WebApplication.CreateBuilder();
        plain.WebHost.UseTestServer();
        _plain = plain.Build();
        _plain.UseRouting();
        MapEcho(_plain);
        await _plain.StartAsync(TestContext.Current.CancellationToken);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(_ => { });
        builder.Services.AddMultiTenancy(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri(Host + Acme),
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        }));

        _multiTenant = builder.Build();
        _multiTenant.UseMultiTenancy();
        MapEcho(_multiTenant);
        _multiTenant.MapOidcEndpoints();
        await _multiTenant.StartAsync(TestContext.Current.CancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        await _plain.DisposeAsync();
        await _multiTenant.DisposeAsync();
    }

    /// <summary>What the host's own endpoint sees of the request that reached it.</summary>
    private static void MapEcho(WebApplication app) => app.MapGet(EchoPath, (HttpContext context) => new
    {
        pathBase = context.Request.PathBase.Value,
        path = context.Request.Path.Value,
        tenant = context.Features.Get<TenantContext>()?.Tenant.Id,
    });

    [Fact]
    public async Task ARequestOutsideEveryTenantReachesTheHostAsWithoutTheLibrary()
    {
        var expected = await EchoAsync(_plain, EchoPath);
        var actual = await EchoAsync(_multiTenant, EchoPath);

        Assert.True(JsonNode.DeepEquals(expected, actual), $"{expected} != {actual}");
    }

    /// <summary>
    /// The resolution is at work in this host: the same endpoint under a tenant's path is told the tenant, which is
    /// what makes the untouched request above a finding rather than a host with no resolution in it.
    /// </summary>
    [Fact]
    public async Task ARequestUnderATenantsPathIsToldTheTenant()
    {
        var seen = await EchoAsync(_multiTenant, Acme + EchoPath);

        Assert.Equal("acme", seen?["tenant"]?.GetValue<string>());
        Assert.Equal(Acme, seen?["pathBase"]?.GetValue<string>());
        Assert.Equal(EchoPath, seen?["path"]?.GetValue<string>());
    }

    private static async Task<JsonNode?> EchoAsync(WebApplication app, string path)
    {
        using var client = app.GetTestClient();
        client.BaseAddress = new Uri(Host);
        using var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();
        return JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
}
