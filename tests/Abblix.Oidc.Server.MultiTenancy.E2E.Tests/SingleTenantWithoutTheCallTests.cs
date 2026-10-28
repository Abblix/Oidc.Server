// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A host declaring one tenant in its options, at an issuer without a path, serves it without calling
/// <c>UseMultiTenancy()</c>; every other host still needs the call and is told why it does not start without it.
/// </summary>
public sealed class SingleTenantWithoutTheCallTests
{
    private const string Host = "https://auth.example.com";
    private const string ClientId = "single-tenant-client";
    private const string ClientSecret = "single-tenant-secret";

    /// <summary>
    /// One tenant at the root of its host is served without the call: discovery answers with its issuer, and a token
    /// request is issued a token carrying it.
    /// </summary>
    [Fact]
    public async Task OneTenantAtTheRoot_IsServedWithoutTheCall()
    {
        await using var app = await StartAsync([Tenant("acme", Host)]);
        using var http = Client(app);

        using var discovery = await http.GetAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, discovery.StatusCode);
        Assert.Equal(Host, (await ReadJsonAsync(discovery))[ConfigurationResponse.Parameters.Issuer]?.GetValue<string>());

        using var token = await RequestTokenAsync(http);
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        Assert.Equal(Host, IssuerOf((await ReadJsonAsync(token))[ResponseParameters.AccessToken]!.GetValue<string>()));
    }

    /// <summary>
    /// Without the call a request under a path base the host set is not served as the tenant, since a root issuer
    /// does not cover it, while one at the root still is.
    /// </summary>
    [Fact]
    public async Task ARequestUnderAPathBase_IsNotServedAsTheTenant()
    {
        await using var app = await StartAsync([Tenant("acme", Host)], pathBase: "/x");
        using var http = Client(app);

        using var underPathBase = await http.GetAsync("/x/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        using var atTheRoot = await http.GetAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, underPathBase.StatusCode);
        Assert.Equal(HttpStatusCode.OK, atTheRoot.StatusCode);
    }

    /// <summary>
    /// With the call in the pipeline the one tenant is resolved as before: a request on another host name reaches no
    /// tenant, rather than being served as the one.
    /// </summary>
    [Fact]
    public async Task WithTheCall_ARequestOnAnotherHost_ReachesNoTenant()
    {
        await using var app = await StartAsync([Tenant("acme", Host)], callsMultiTenancy: true);
        using var http = app.GetTestClient();
        http.BaseAddress = new Uri("https://other.example.com");

        using var response = await http.GetAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// A tenant whose issuer has a path, several tenants, and a store writer of the host's own each need the call,
    /// and a host leaving it out does not start, told so by name.
    /// </summary>
    [Theory]
    [InlineData("path")]
    [InlineData("several")]
    [InlineData("writer")]
    public async Task AHostNeedingTheCall_DoesNotStartWithoutIt(string why)
    {
        TenantDefinition[] tenants = why switch
        {
            "path" => [Tenant("acme", Host + "/tenants/acme")],
            "several" => [Tenant("acme", Host + "/tenants/acme"), Tenant("globex", Host + "/tenants/globex")],
            "writer" => [Tenant("acme", Host)],
            _ => throw new ArgumentOutOfRangeException(nameof(why), why, null),
        };
        var app = Build(tenants, writer: why == "writer");

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => app.StartAsync(TestContext.Current.CancellationToken));

        Assert.Contains(nameof(MultiTenancyExtensions.UseMultiTenancy), refusal.Message, StringComparison.Ordinal);
        await app.DisposeAsync();
    }

    /// <summary>
    /// A server serving its one tenant without the call changes no tenant while it runs, and an attempt to create one
    /// is refused naming the call it would need.
    /// </summary>
    [Fact]
    public async Task CreatingATenantWithoutTheCall_IsRefusedNamingIt()
    {
        await using var app = await StartAsync([Tenant("acme", Host)]);
        var manager = app.Services.GetRequiredService<ITenantManager>();

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => manager.CreateAsync(Tenant("globex", Host + "/tenants/globex"), TestContext.Current.CancellationToken));

        Assert.Contains(nameof(MultiTenancyExtensions.UseMultiTenancy), refusal.Message, StringComparison.Ordinal);
    }

    private static async Task<WebApplication> StartAsync(
        TenantDefinition[] tenants,
        string? pathBase = null,
        bool callsMultiTenancy = false)
    {
        var app = Build(tenants, pathBase: pathBase, callsMultiTenancy: callsMultiTenancy);
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static WebApplication Build(
        TenantDefinition[] tenants,
        bool writer = false,
        string? pathBase = null,
        bool callsMultiTenancy = false)
    {
        TestLicense.Loaded.GetAwaiter().GetResult();

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base;
            foreach (var tenant in tenants)
                options.Tenants.Add(tenant);
        });

        if (writer)
            builder.Services.AddSingleton<ITenantStoreWriter>(new MemoryTenantStore());

        var app = builder.Build();
        if (pathBase is not null)
            app.UsePathBase(pathBase);

        if (callsMultiTenancy)
            app.UseMultiTenancy();
        else
            app.UseRouting();

        app.UseCors();
        app.MapOidcEndpoints();
        return app;
    }

    private static TenantDefinition Tenant(string id, string issuer) => new()
    {
        Id = id,
        Issuer = new Uri(issuer),
        Clients =
        [
            new ClientInfo(ClientId)
            {
                ClientSecrets =
                [
                    new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) },
                ],
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                AllowedGrantTypes = [GrantTypes.ClientCredentials],
            },
        ],
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    private static HttpClient Client(WebApplication app)
    {
        var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);
        return http;
    }

    private static Task<HttpResponseMessage> RequestTokenAsync(HttpClient http)
        => http.PostAsync(
            "/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
            TestContext.Current.CancellationToken);

    private static async Task<JsonNode> ReadJsonAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;

    private static string? IssuerOf(string jwt)
    {
        var payload = jwt.Split('.')[1];
        payload += new string('=', (4 - payload.Length % 4) % 4);
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/')));
        return JsonNode.Parse(json)?[IanaClaimTypes.Iss]?.GetValue<string>();
    }
}
