// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A sign-in session belongs to the tenant it was signed in at: its cookie carried to another tenant, by a shared
/// cookie domain or a path a host widened, is not taken there as a session of that tenant's user of the same id.
/// </summary>
public sealed class SessionTenantBindingTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string SignInPath = "/host/sign-in";
    private const string WhoAmIPath = "/host/who-am-i";

    private WebApplication _app = null!;
    private HttpClient _http = null!;

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddSingleton<IUserInfoProvider, NoUserInfoProvider>();
        builder.Services.AddOidcServices(_ => { });
        builder.Services.AddMultiTenancy(options =>
        {
            options.Tenants.Add(Tenant("acme", Acme));
            options.Tenants.Add(Tenant("globex", Globex));
        });

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseCors();
        _app.MapPost(SignInPath, async (IAuthSessionService sessions, TimeProvider clock) =>
        {
            await sessions.SignInAsync(new AuthSession("alice", "alice-session", clock.GetUtcNow(), "local"));
            return Results.NoContent();
        });
        _app.MapGet(WhoAmIPath, async (IAuthSessionService sessions)
            => (await sessions.AuthenticateAsync())?.Subject is { } subject ? Results.Text(subject) : Results.NoContent());
        _app.MapOidcEndpoints();
        await _app.StartAsync(TestContext.Current.CancellationToken);

        _http = _app.GetTestClient();
        _http.BaseAddress = new Uri(Host);
    }

    public async ValueTask DisposeAsync()
    {
        _http.Dispose();
        await _app.DisposeAsync();
    }

    private static TenantDefinition Tenant(string id, string path) => new()
    {
        Id = id,
        Issuer = new Uri(Host + path),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    [Fact]
    public async Task A_session_of_one_tenant_is_not_taken_at_another()
    {
        var cookie = await SignInAtAsync(Acme);

        Assert.Equal("alice", await WhoIsSignedInAtAsync(Acme, cookie));
        Assert.Null(await WhoIsSignedInAtAsync(Globex, cookie));
    }

    /// <summary>
    /// Signs alice in at <paramref name="tenant"/> and answers the cookie the browser was handed, as a Cookie header.
    /// </summary>
    private async Task<string> SignInAtAsync(string tenant)
    {
        using var response = await _http.PostAsync(tenant + SignInPath, null, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var setCookie = Assert.Single(response.Headers.GetValues("Set-Cookie"));
        return setCookie[..setCookie.IndexOf(';')];
    }

    /// <summary>
    /// Who the session the cookie carries is at <paramref name="tenant"/>, whatever path the cookie was set for.
    /// </summary>
    private async Task<string?> WhoIsSignedInAtAsync(string tenant, string cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, tenant + WhoAmIPath);
        request.Headers.Add("Cookie", cookie);
        using var response = await _http.SendAsync(request, TestContext.Current.CancellationToken);
        return response.StatusCode == HttpStatusCode.OK
            ? await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)
            : null;
    }
}
