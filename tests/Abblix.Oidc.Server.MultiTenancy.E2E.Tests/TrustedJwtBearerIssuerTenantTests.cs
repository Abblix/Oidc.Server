// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A tenant at the issuer of a trusted JWT bearer issuer is refused wherever it enters the server, since the grant
/// reads nothing this server records about its own tokens and the tenant's revoked tokens would pass as assertions.
/// </summary>
public sealed class TrustedJwtBearerIssuerTenantTests
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";

    /// <summary>
    /// A server whose settings declare a tenant at the trusted issuer does not start, and the same server declaring the
    /// tenant at another issuer does, so the refusal is the trusted issuer's.
    /// </summary>
    [Fact]
    public async Task ATenantDeclaredAtATrustedIssuer_StopsTheServer()
    {
        await using (var starts = await BuildAsync(store: null, Tenant("acme", Acme)))
            await starts.StartAsync(TestContext.Current.CancellationToken);

        // Building the endpoints already reads the settings, so the refusal may come before the start itself
        await Assert.ThrowsAsync<OptionsValidationException>(async () =>
        {
            await using var app = await BuildAsync(store: null, Tenant("globex", Globex));
            await app.StartAsync(TestContext.Current.CancellationToken);
        });
    }

    /// <summary>
    /// A tenant created at the trusted issuer, or changed to it, is refused, and the tenant changed so stays where it
    /// was; the server serving a tenant at another issuer starts, so the refusals are not a server that refuses
    /// everything.
    /// </summary>
    [Fact]
    public async Task ATenantAtATrustedIssuer_IsRefused_WhenCreatedOrChanged()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(Tenant("acme", Acme), ct);
        await using var app = await BuildAsync(store);
        await app.StartAsync(ct);
        var manager = app.Services.GetRequiredService<ITenantManager>();

        Assert.Equal(TenantChangeRefusalReason.Invalid, Refused(await manager.CreateAsync(Tenant("globex", Globex), ct)));

        var acme = Assert.Single(await store.ListAsync(ct));
        Assert.Equal(
            TenantChangeRefusalReason.Invalid,
            Refused(await manager.UpdateAsync(Tenant("acme", Globex, acme.Tenant.Generation), acme.Version, ct)));
        Assert.Equal(Host + Acme, Assert.Single(await store.ListAsync(ct)).Tenant.Issuer.OriginalString);
    }

    private static async Task<WebApplication> BuildAsync(MemoryTenantStore? store, params TenantDefinition[] declared)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base;
            foreach (var tenant in declared)
                options.Tenants.Add(tenant);

            options.JwtBearer = new JwtBearerOptions
            {
                TrustedIssuers =
                [
                    new TrustedIssuer { Issuer = Host + Globex, JwksUri = new Uri("https://idp.example.com/jwks") },
                ],
            };
        });

        if (store is not null)
        {
            builder.Services.AddSingleton<ITenantStore>(store);
            builder.Services.AddSingleton<ITenantStoreWriter>(store);
        }

        var app = builder.Build();
        app.UseMultiTenancy();
        app.MapOidcEndpoints();
        return app;
    }

    private static TenantDefinition Tenant(string id, string path, string generation = "") => new()
    {
        Id = id,
        Generation = generation,
        Issuer = new Uri(Host + path),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    private static TenantChangeRefusalReason Refused(Result<StoredTenant, TenantChangeRefusal> result)
        => result.Match(_ => throw new Xunit.Sdk.XunitException("The change was made."), refusal => refusal.Reason);
}
