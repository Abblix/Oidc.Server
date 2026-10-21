// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.MinimalApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using Abblix.Oidc.Server.Features.Consents;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// A server let run on an http issuer, for local development, is served over http: its endpoints do not send the
/// client to https, which such a server does not listen on.
/// </summary>
public sealed class HttpIssuerTests(HttpIssuerTests.HttpLetThroughFactory httpsFactory)
    : IClassFixture<HttpIssuerTests.HttpLetThroughFactory>
{
    /// <summary>
    /// A server whose issuer is https still sends a request over http to https, with http issuers let through.
    /// </summary>
    [Fact]
    public async Task Discovery_OfAnHttpsIssuer_ReachedOverHttp_IsRedirected()
    {
        using var client = httpsFactory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = HttpsIssuerOverHttp,
        });
        using var response = await client.GetAsync(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(Uri.UriSchemeHttps, response.Headers.Location?.Scheme);
    }

    /// <summary>
    /// The keys of an http issuer are served over http. The keys rather than discovery, which the license of this
    /// suite would refuse for an issuer it does not name, and the tenant from a store of the host's own, since the
    /// license refuses at startup a tenant of the settings it does not name.
    /// </summary>
    [Fact]
    public async Task TheKeys_OfAnHttpIssuer_AreServedOverHttp()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddSingleton<ITenantStore>(new OneTenant(new TenantDefinition
        {
            Id = "local",
            Issuer = HttpAddress,
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        }));
        builder.Services.AddOidcServices(options => options.AllowHttpIssuer = true);
        await using var app = builder.Build();
        app.UseMultiTenancy();
        app.UseCors();
        app.MapOidcEndpoints();
        await app.StartAsync(TestContext.Current.CancellationToken);

        using var client = app.GetTestClient();
        client.BaseAddress = HttpAddress;
        using var response = await client.GetAsync("/.well-known/jwks", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// The sample host, whose issuer is https, with http issuers let through.
    /// </summary>
    public sealed class HttpLetThroughFactory : TestFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.AllowHttpIssuer = true)));
        }
    }

    /// <summary>A store of the host's own holding one tenant.</summary>
    private sealed class OneTenant(TenantDefinition tenant) : ITenantStore
    {
        public Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyCollection<StoredTenant>>([new StoredTenant(tenant, "1")]);
    }

    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "In-memory TestServer base address; not a deployment URL.")]
    private static readonly Uri HttpAddress = new("http://localhost");

    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "In-memory TestServer base address; not a deployment URL.")]
    private static readonly Uri HttpsIssuerOverHttp = new("http://auth.example.com");
}
