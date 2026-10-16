// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A tenant the settings declare that the license in force would refuse on every request stops the server at
/// startup, rather than leaving it to answer that tenant's requests with errors.
/// </summary>
public sealed class TenantLicenseStartupTests
{
    private const string Host = "https://auth.example.com";

    [Fact]
    public async Task A_tenant_whose_issuer_the_license_does_not_name_stops_the_server()
    {
        await TestLicense.Loaded;
        await using var app = Build("/tenants/acme", "/tenants/initech");

        await Assert.ThrowsAsync<OptionsValidationException>(
            () => app.StartAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Tenants_whose_issuers_the_license_names_start()
    {
        await TestLicense.Loaded;
        await using var app = Build("/tenants/acme", "/tenants/globex");

        await app.StartAsync(TestContext.Current.CancellationToken);

        using var client = app.GetTestClient();
        using var discovery = await client.GetAsync(
            Host + "/tenants/globex/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.OK, discovery.StatusCode);
    }

    private static WebApplication Build(params string[] issuerPaths)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddSingleton<IUserInfoProvider, NoUserInfoProvider>();
        builder.Services.AddOidcServices(_ => { });
        builder.Services.AddMultiTenancy(options =>
        {
            foreach (var path in issuerPaths)
            {
                options.Tenants.Add(new TenantDefinition
                {
                    Id = path[(path.LastIndexOf('/') + 1)..],
                    Issuer = new Uri(Host + path),
                    SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
                });
            }
        });

        var app = builder.Build();
        app.UseMultiTenancy();
        app.UseCors();
        app.MapOidcEndpoints();
        return app;
    }
}
