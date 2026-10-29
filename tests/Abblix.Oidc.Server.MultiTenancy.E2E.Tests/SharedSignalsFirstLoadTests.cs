// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Security.Claims;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// On a host serving its one tenant without <c>UseMultiTenancy()</c>, a request to the transmitter's endpoints that
/// arrives while the tenant is still being loaded at startup gets the answer it gets once the load has completed.
/// </summary>
public sealed class SharedSignalsFirstLoadTests
{
    private const string Host = "https://auth.example.com";
    private const string ConfigurationDocument = "/.well-known/ssf-configuration";
    private const string StreamPath = "/ssf/stream";
    private const string ReceiverId = "https://receiver.example.com";
    private const string SubjectHeader = "X-Test-Subject";

    // Long enough for a request that does not wait for the load to be answered
    private static readonly TimeSpan WhileTheLoadIsHeld = TimeSpan.FromSeconds(2);

    // Long beyond any start, short of a run that hangs
    private static readonly TimeSpan StartBound = TimeSpan.FromSeconds(30);

    /// <summary>The start orders in which a server may take requests before its tenants are loaded.</summary>
    public enum StartOrder
    {
        /// <summary>The host starts its services at once.</summary>
        Concurrent,

        /// <summary>The server is registered after the web host, so the web host starts first.</summary>
        ServerAfterTheWebHost,
    }

    /// <summary>
    /// The configuration document is answered 200 once the load completes, a stream management request without
    /// credentials 401, and a receiver's request for its streams 200, as each is on a loaded server, rather than 404 for
    /// a transmitter not there yet. The receiver's request reaches the handler, which uses the transmitter's parts
    /// bound for the request, so it is answered from the tenant's transmitter only when the wait comes before binding.
    /// </summary>
    [Theory]
    [InlineData(StartOrder.Concurrent, ConfigurationDocument, false, HttpStatusCode.OK)]
    [InlineData(StartOrder.ServerAfterTheWebHost, ConfigurationDocument, false, HttpStatusCode.OK)]
    [InlineData(StartOrder.Concurrent, StreamPath, false, HttpStatusCode.Unauthorized)]
    [InlineData(StartOrder.ServerAfterTheWebHost, StreamPath, false, HttpStatusCode.Unauthorized)]
    [InlineData(StartOrder.Concurrent, StreamPath, true, HttpStatusCode.OK)]
    [InlineData(StartOrder.ServerAfterTheWebHost, StreamPath, true, HttpStatusCode.OK)]
    public async Task ARequestDuringTheFirstLoad_IsAnsweredAsOnceLoaded(
        StartOrder order,
        string path,
        bool asReceiver,
        HttpStatusCode answer)
    {
        var ct = TestContext.Current.CancellationToken;
        await TestLicense.Loaded;
        var preparation = new HeldPreparation();
        var arrival = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var host = Build(order, preparation, arrival);

        var start = host.StartAsync(ct);
        await preparation.Entered.Task.WaitAsync(StartBound, ct);
        using var http = host.GetTestClient();
        http.BaseAddress = new Uri(Host);
        if (asReceiver)
            http.DefaultRequestHeaders.Add(SubjectHeader, ReceiverId);

        var request = http.GetAsync(path, ct);

        // The request is inside the server while the load is held open, and a server that did not wait for the load
        // answers it within the bound
        await arrival.Task.WaitAsync(StartBound, ct);
        await Task.WhenAny(request, Task.Delay(WhileTheLoadIsHeld, ct));
        Assert.False(request.IsCompleted);

        preparation.Release.SetResult();
        await start;

        using var response = await request;
        Assert.Equal(answer, response.StatusCode);
        await host.StopAsync(ct);
    }

    private static IHost Build(StartOrder order, HeldPreparation preparation, TaskCompletionSource arrival)
    {
        void Pipeline(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                arrival.TrySetResult();
                await next(context);
            });

            // What a host's bearer authentication leaves behind: the receiver, and the issuer of its credentials
            app.Use((context, next) =>
            {
                if (context.Request.Headers.TryGetValue(SubjectHeader, out var subject))
                {
                    Claim[] claims =
                    [
                        new(IanaClaimTypes.Sub, subject.ToString()),
                        new(IanaClaimTypes.Iss, Host),
                    ];
                    context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
                }

                return next(context);
            });
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapOidcEndpoints();
                endpoints.MapSharedSignalsTransmitterEndpoints();
            });
        }

        return order switch
        {
            StartOrder.Concurrent => new HostBuilder()
                .ConfigureServices(services =>
                    services.Configure<HostOptions>(options => options.ServicesStartConcurrently = true))
                .ConfigureServices(services => Register(services, preparation))
                .ConfigureWebHost(web => web.UseTestServer().Configure(Pipeline))
                .Build(),

            StartOrder.ServerAfterTheWebHost => new HostBuilder()
                .ConfigureWebHost(web => web.UseTestServer().Configure(Pipeline))
                .ConfigureServices(services => Register(services, preparation))
                .Build(),

            _ => throw new ArgumentOutOfRangeException(nameof(order), order, null),
        };
    }

    private static void Register(IServiceCollection services, HeldPreparation preparation)
    {
        services.AddRouting();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddConsentGrantedForEveryClient();
        var server = services.AddOidcServices(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri(Host),
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
        }));
        services.AddSecurityEvents();
        services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = Host,
            JwksUri = new Uri(Host + "/.well-known/jwks"),
        });
        server.AddSharedSignals();
        services.AddSingleton<ITenantOpening>(preparation);
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
