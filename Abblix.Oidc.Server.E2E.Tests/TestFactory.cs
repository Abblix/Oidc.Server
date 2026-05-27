// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// Boots the TestHost OIDC provider in-memory for E2E flow tests. Only
/// test-mode tweaks the production host doesn't ship with — open DCR
/// (no Initial Access Token) — are applied here; everything else is
/// what a real consumer of Abblix.Oidc.Server gets.
/// </summary>
public class TestFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Test");

        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                new PostConfigureOptions<OidcOptions>(
                    Options.DefaultName,
                    options => options.RequireInitialAccessToken = false));
        });
    }

    protected override void ConfigureClient(HttpClient client)
    {
        // OIDC MVC controllers carry [RequireHttps]; force the in-memory
        // TestServer client to https://localhost so Request.IsHttps == true.
        client.BaseAddress = new Uri("https://localhost");
    }
}
