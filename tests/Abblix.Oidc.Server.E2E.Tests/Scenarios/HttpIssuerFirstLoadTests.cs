// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Jwt;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
#if MINIMAL_API_TRANSPORT
using Abblix.Oidc.Server.MinimalApi;
#else
using Abblix.Oidc.Server.Mvc;
#endif

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A server serving its one tenant at an http issuer, without <c>UseMultiTenancy()</c>, answers a request over http
/// that arrives while the tenant is still being loaded at startup as it answers one arriving afterwards.
/// </summary>
public sealed class HttpIssuerFirstLoadTests
{
    // An issuer the suite's license names, so the server serves it
    private const string Issuer = "http://auth.example.com";

    // Long enough for a request that does not wait for the load to be answered
    private static readonly TimeSpan WhileTheLoadIsHeld = TimeSpan.FromSeconds(2);

    // Long beyond any start, short of a run that hangs
    private static readonly TimeSpan StartBound = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The HTTPS requirement reads the tenant to let an http issuer through, so a request judged before the tenant is
    /// loaded would be sent to https; it waits for the load instead and is served over http.
    /// </summary>
    [Fact]
    public async Task ARequestOverHttpDuringTheFirstLoad_IsServedOverHttp()
    {
        var ct = TestContext.Current.CancellationToken;
        var preparation = new HeldPreparation();
        var arrival = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var app = Build(preparation, arrival);

        var start = app.StartAsync(ct);
        await preparation.Entered.Task.WaitAsync(StartBound, ct);
        using var http = app.GetTestClient();
        http.BaseAddress = new Uri(Issuer);
        var discovery = http.GetAsync("/.well-known/openid-configuration", ct);

        // The request is inside the server while the load is held open, and a server judging it before the load
        // answers it within the bound
        await arrival.Task.WaitAsync(StartBound, ct);
        await Task.WhenAny(discovery, Task.Delay(WhileTheLoadIsHeld, ct));
        Assert.False(discovery.IsCompleted);

        preparation.Release.SetResult();
        await start;

        using var response = await discovery;
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await app.StopAsync(ct);
    }

    private static WebApplication Build(HeldPreparation preparation, TaskCompletionSource arrival)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.Configure<HostOptions>(options => options.ServicesStartConcurrently = true);
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
#if !MINIMAL_API_TRANSPORT
        builder.Services.AddControllers();
#endif
        builder.Services.AddOidcServices(options =>
        {
            options.AllowHttpIssuer = true;
            options.Tenants.Add(new TenantDefinition
            {
                Id = TestTenantSettings.TenantId,
                Issuer = new Uri(Issuer),
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
            });
        });
        builder.Services.AddSingleton<ITenantOpening>(preparation);

        var app = builder.Build();
        app.Use(async (context, next) =>
        {
            arrival.TrySetResult();
            await next(context);
        });
        app.UseRouting();
        app.UseCors();
#if MINIMAL_API_TRANSPORT
        app.MapOidcEndpoints();
#else
        app.MapControllers();
        app.MapOidcControllers();
#endif
        return app;
    }

    /// <summary>
    /// A preparation of the tenants that holds the load open until the test releases it.
    /// </summary>
    private sealed class HeldPreparation : ITenantOpening
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
            IReadOnlyCollection<TenantDefinition> tenants,
            CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            await Release.Task;
            return new Dictionary<string, Exception>();
        }
    }
}
