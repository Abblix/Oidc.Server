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
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A tenant holding a null where its definition declares a value, as a database row or a configuration file can, is
/// refused like any other invalid tenant: a store's tenant is left out while the others are served, and a tenant of
/// the settings refuses the start naming the value.
/// </summary>
public sealed class TenantWithANullTests
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "acme";
    private const string Globex = "globex";
    private const string ClientId = "web";

    /// <summary>
    /// The JSON a store holds for globex, with the member at <paramref name="path"/> written as
    /// <paramref name="value"/>, is read by System.Text.Json as a store reads it: globex is left out and acme is
    /// served.
    /// </summary>
    [Theory]
    [InlineData("Resources", "[{}]")]
    [InlineData("Resources", """[{"Resource":null}]""")]
    [InlineData("Resources", "[null]")]
    [InlineData("Clients", "null")]
    [InlineData("Clients", "[null]")]
    [InlineData("Clients/0/ClientSecrets", "[null]")]
    [InlineData("Clients/0/RedirectUris", "null")]
    [InlineData("Clients/0/RedirectUris", "[null]")]
    [InlineData("Clients/0/PostLogoutRedirectUris", "null")]
    [InlineData("Clients/0/AllowedGrantTypes", "[null]")]
    [InlineData("Clients/0/AllowedScopes", "[null]")]
    [InlineData("Clients/0/TokenEndpointAuthMethod", "null")]
    [InlineData("Scopes", "[null]")]
    [InlineData("SigningKeys", "null")]
    public async Task ATenantOfTheStoreWithANull_IsLeftOut_AndTheOthersAreServed(string path, string value)
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(Tenant(Acme), ct);
        await store.AddAsync(FromStoredJson(Tenant(Globex), path, value), ct);

        await using var app = Build(services => services.AddSingleton<ITenantStore>(store), _ => { });
        await app.StartAsync(ct);
        using var http = app.GetTestClient();

        using var acme = await http.GetAsync(Discovery(Acme), ct);
        using var globex = await http.GetAsync(Discovery(Globex), ct);

        Assert.Equal(HttpStatusCode.OK, acme.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, globex.StatusCode);
    }

    /// <summary>
    /// A tenant refused for a null still holds its address: another tenant created there is refused for the
    /// conflict, and one the store already holds there is left out, as beside a tenant refused for anything else.
    /// </summary>
    [Fact]
    public async Task ATenantRefusedForANull_KeepsItsAddressFromAnother()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(Tenant(Acme), ct);
        await store.AddAsync(FromStoredJson(Tenant(Globex), "Clients/0/RedirectUris", "null"), ct);

        await using var app = Build(
            services => services.AddSingleton<ITenantStore>(store).AddSingleton<ITenantStoreWriter>(store),
            _ => { });
        await app.StartAsync(ct);

        var impostor = Tenant("initech");
        impostor = new TenantDefinition
        {
            Id = impostor.Id,
            Issuer = new Uri($"{Host}/tenants/{Globex}"),
            Clients = impostor.Clients,
            SigningKeys = impostor.SigningKeys,
        };
        var created = await app.Services.GetRequiredService<ITenantManager>().CreateAsync(impostor, ct);

        Assert.True(created.TryGetFailure(out var refusal));
        Assert.Equal(TenantChangeRefusalReason.Invalid, refusal.Reason);

        await store.AddAsync(impostor, ct);
        await app.Services.GetRequiredService<StoreTenantCatalog>().RefreshAsync(ct);
        using var http = app.GetTestClient();
        using var globex = await http.GetAsync(Discovery(Globex), ct);
        using var acme = await http.GetAsync(Discovery(Acme), ct);

        Assert.Equal(HttpStatusCode.NotFound, globex.StatusCode);
        Assert.Equal(HttpStatusCode.OK, acme.StatusCode);
    }

    /// <summary>
    /// The same JSON with nothing replaced serves both tenants, so a tenant left out above is left out for the null.
    /// </summary>
    [Fact]
    public async Task TheStoredJsonWithNoNull_ServesBothTenants()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(Tenant(Acme), ct);
        await store.AddAsync(JsonSerializer.SerializeToNode(Tenant(Globex))!.Deserialize<TenantDefinition>()!, ct);

        await using var app = Build(services => services.AddSingleton<ITenantStore>(store), _ => { });
        await app.StartAsync(ct);
        using var http = app.GetTestClient();

        using var acme = await http.GetAsync(Discovery(Acme), ct);
        using var globex = await http.GetAsync(Discovery(Globex), ct);

        Assert.Equal(HttpStatusCode.OK, acme.StatusCode);
        Assert.Equal(HttpStatusCode.OK, globex.StatusCode);
    }

    /// <summary>
    /// A client of the settings bound from a configuration file holding a null refuses the start, naming the tenant,
    /// the client and the member. The binder reads a null element of a collection of strings or addresses as null,
    /// while one of a collection of objects, such as the secrets, becomes an empty object the checks judge.
    /// </summary>
    [Theory]
    [InlineData("PostLogoutRedirectUris", """{"ClientId":"web","PostLogoutRedirectUris":[null]}""")]
    [InlineData("RedirectUris", """{"ClientId":"web","RedirectUris":[null]}""")]
    [InlineData("AllowedGrantTypes", """{"ClientId":"web","AllowedGrantTypes":[null]}""")]
    public async Task ATenantOfTheSettingsWithANull_RefusesTheStart_NamingTheValue(string member, string client)
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes($$"""{"Client":{{client}}}""")))
            .Build();
        var bound = configuration.GetSection("Client").Get<ClientInfo>()!;

        // The settings are read as the endpoints are mapped, so the refusal may come before the start itself
        var refusal = await Assert.ThrowsAsync<OptionsValidationException>(async () =>
        {
            await using var app = Build(_ => { }, options =>
            {
                options.Tenants.Add(Tenant(Acme));
                options.Tenants.Add(Tenant(Globex, bound));
            });
            await app.StartAsync(TestContext.Current.CancellationToken);
        });

        var failure = Assert.Single(refusal.Failures);
        Assert.Contains($"'{Globex}'", failure, StringComparison.Ordinal);
        Assert.Contains($"'{ClientId}'", failure, StringComparison.Ordinal);
        Assert.Contains(member, failure, StringComparison.Ordinal);
    }

    private static string Discovery(string tenantId) => $"{Host}/tenants/{tenantId}/.well-known/openid-configuration";

    /// <summary>
    /// <paramref name="tenant"/> written to JSON, the member at <paramref name="path"/> replaced with
    /// <paramref name="value"/>, and read back.
    /// </summary>
    private static TenantDefinition FromStoredJson(TenantDefinition tenant, string path, string value)
    {
        var json = JsonSerializer.SerializeToNode(tenant)!;
        var segments = path.Split('/');
        var parent = segments[..^1].Aggregate(json, (node, segment)
            => int.TryParse(segment, out var index) ? node[index]! : node[segment]!);
        parent[segments[^1]] = JsonNode.Parse(value);
        return json.Deserialize<TenantDefinition>()!;
    }

    private static TenantDefinition Tenant(string id, ClientInfo? client = null)
    {
        var scope = new ScopeDefinition("orders", "order_id");
        return new TenantDefinition
        {
            Id = id,
            Issuer = new Uri($"{Host}/tenants/{id}"),
            Clients =
            [
                client ?? new ClientInfo(ClientId)
                {
                    ClientSecrets = [new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes("secret")) }],
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                    AllowedGrantTypes = [GrantTypes.AuthorizationCode],
                    AllowedScopes = [Scopes.OpenId],
                    RedirectUris = [new Uri("https://client.example.com/callback")],
                    PostLogoutRedirectUris = [new Uri("https://client.example.com/")],
                },
            ],
            Scopes = [scope],
            Resources = [new ResourceDefinition(new Uri("https://api.example.com"), scope)],
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
        };
    }

    private static WebApplication Build(Action<IServiceCollection> services, Action<OidcOptions> configure)
    {
        TestLicense.Loaded.GetAwaiter().GetResult();

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(configure);
        services(builder.Services);

        var app = builder.Build();
        app.UseMultiTenancy();
        app.UseCors();
        app.MapOidcEndpoints();
        return app;
    }
}
