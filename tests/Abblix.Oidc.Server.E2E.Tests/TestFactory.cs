// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// Boots the TestHost OIDC provider in-memory for E2E flow tests. Only
/// test-mode tweaks the production host doesn't ship with - open DCR
/// (no Initial Access Token) - are applied here; everything else is
/// what a real consumer of Abblix.Oidc.Server gets.
/// </summary>
public class TestFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    /// <summary>
    /// Eagerly builds the single shared host once, before the parallel test classes touch it.
    /// WebApplicationFactory builds its host lazily on first access and its EnsureServer step is
    /// not thread-safe; under the assembly-fixture + parallel-collection model, concurrent
    /// first-access would otherwise build the host more than once - each build mints a fresh
    /// signing key and gets its own isolated in-memory stores, so a token issued through one
    /// build fails signature validation (or grant lookup) against another. Forcing the build here,
    /// single-threaded, removes that race. This is test-infrastructure correctness, not behaviour.
    /// </summary>
    public ValueTask InitializeAsync()
    {
        _ = Server;
        return ValueTask.CompletedTask;
    }

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
        client.BaseAddress = TestServerAddress.BaseAddress;
    }
}
