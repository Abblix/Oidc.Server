// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// Boots the Minimal API TestHost OIDC provider in-memory. The host wires the framework-neutral
/// core through <c>AddOidcMinimalApi</c> + <c>MapOidcEndpoints</c>, so these tests exercise the
/// generated request models' <c>BindAsync</c> and the <c>IResult</c> formatters over a real ASP.NET
/// Core request pipeline — the same way a consumer of the Abblix.Oidc.Server.MinimalApi package would.
/// </summary>
public sealed class TestFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "In-memory TestServer base address; not a deployment URL.")]
    private static readonly Uri Base = new("https://localhost");

    /// <summary>
    /// Eagerly builds the single shared host once, single-threaded, before parallel test methods
    /// touch it: WebApplicationFactory builds lazily and its EnsureServer step is not thread-safe,
    /// and each build mints a fresh signing key, so a token issued through one build would fail
    /// validation against another. Forcing the build here removes that race.
    /// </summary>
    public ValueTask InitializeAsync()
    {
        _ = Server;
        return ValueTask.CompletedTask;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Test");

        // Open dynamic client registration (no initial access token) is the only test-mode tweak a real
        // consumer would not ship; everything else is the stock Abblix.Oidc.Server.MinimalApi behavior.
        builder.ConfigureTestServices(services =>
            services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                new PostConfigureOptions<OidcOptions>(
                    Options.DefaultName,
                    options => options.RequireInitialAccessToken = false)));
    }

    protected override void ConfigureClient(HttpClient client) => client.BaseAddress = Base;
}
