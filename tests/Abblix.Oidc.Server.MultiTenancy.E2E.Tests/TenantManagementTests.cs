// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Tenants created, changed and removed through the manager of the tenants while the server runs: the instance
/// that made a change serves it on the next request, with no restart and no wait for the next reading of the store.
/// </summary>
public sealed class TenantManagementTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string AcmeClient = "acme-client";
    private const string Globex = "/tenants/globex";
    private const string TokenPath = "/connect/token";
    private const string ConfigurationPath = "/.well-known/openid-configuration";
    private const string ClientSecret = "tenant-client-secret";

    private readonly MemoryTenantStore _store = new();
    private WebApplication? _app;
    private HttpClient? _http;

    private HttpClient Http => _http!;

    private ITenantManager Manager => _app!.Services.GetRequiredService<ITenantManager>();

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        // The server starts with one tenant in the store; every other change reaches it through the manager
        await _store.AddAsync(
            Tenant("acme", Acme, AcmeClient, Guid.NewGuid().ToString("N")),
            TestContext.Current.CancellationToken);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton<IUserInfoProvider, NoUserInfoProvider>();
        builder.Services.AddOidcServices(options => options.EnabledEndpoints = OidcEndpoints.Base);

        builder.Services.AddSingleton<ITenantStore>(_store);
        builder.Services.AddSingleton<ITenantStoreWriter>(_store);
        builder.Services.AddMultiTenancy(_ => { });

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseCors();
        _app.UseAuthorization();
        _app.MapOidcEndpoints();

        await _app.StartAsync(TestContext.Current.CancellationToken);

        _http = _app.GetTestClient();
        _http.BaseAddress = new Uri(Host);
    }

    public async ValueTask DisposeAsync()
    {
        _http?.Dispose();
        if (_app is not null)
            await _app.DisposeAsync();
    }

    private static TenantDefinition Tenant(string id, string path, string clientId, string generation = "") => new()
    {
        Id = id,
        Generation = generation,
        Issuer = Host + path,
        Clients =
        [
            new ClientInfo(clientId)
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

    private Task<HttpResponseMessage> RequestTokenAsync(string tenant, string clientId)
        => Http.PostAsync(
            tenant + TokenPath,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
                [ClientRequest.Parameters.ClientId] = clientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
            TestContext.Current.CancellationToken);

    private Task<HttpResponseMessage> DiscoverAsync(string tenant)
        => Http.GetAsync(tenant + ConfigurationPath, TestContext.Current.CancellationToken);

    private static async Task<JsonNode> ReadJsonAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;

    private static async Task<string> IssuerOfTheAccessTokenAsync(HttpResponseMessage response)
    {
        var accessToken = (await ReadJsonAsync(response))[ResponseParameters.AccessToken]!.GetValue<string>();
        var payload = JsonNode.Parse(Base64Url.DecodeFromChars(accessToken.Split('.')[1]))!;
        return payload[JwtClaimTypes.Issuer]!.GetValue<string>();
    }

    private async Task<StoredTenant> StoredAsync(string tenantId)
        => (await _store.ListAsync(TestContext.Current.CancellationToken)).Single(
            stored => stored.Tenant.Id == tenantId);

    // A refusal fails the test with its reason and message in view
    private static void AssertMade(Result<StoredTenant, TenantChangeRefusal> result)
        => Assert.Null(result.Match<TenantChangeRefusal?>(_ => null, refusal => refusal));

    /// <summary>
    /// A tenant created while the server runs is served on the next request, and its tokens name its own issuer.
    /// </summary>
    [Fact]
    public async Task ATenantCreatedWhileTheServerRuns_IssuesTokensUnderItsIssuer()
    {
        Assert.Equal(HttpStatusCode.NotFound, (await RequestTokenAsync(Globex, "globex-client")).StatusCode);

        AssertMade(await Manager.CreateAsync(
            Tenant("globex", Globex, "globex-client"),
            TestContext.Current.CancellationToken));

        var response = await RequestTokenAsync(Globex, "globex-client");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Host + Globex, await IssuerOfTheAccessTokenAsync(response));
    }

    /// <summary>
    /// A tenant changed while the server runs is served as changed on the next request: the client it dropped is
    /// refused and the client it gained gets a token.
    /// </summary>
    [Fact]
    public async Task ATenantChangedWhileTheServerRuns_IsServedAsChanged()
    {
        Assert.Equal(HttpStatusCode.OK, (await RequestTokenAsync(Acme, AcmeClient)).StatusCode);
        var stored = await StoredAsync("acme");

        AssertMade(await Manager.UpdateAsync(
            Tenant("acme", Acme, "acme-new-client"),
            stored.Version,
            TestContext.Current.CancellationToken));

        var dropped = await RequestTokenAsync(Acme, AcmeClient);
        Assert.Equal(HttpStatusCode.Unauthorized, dropped.StatusCode);
        Assert.Equal(
            ErrorCodes.InvalidClient,
            (await ReadJsonAsync(dropped))[ResponseParameters.Error]?.GetValue<string>());

        var gained = await RequestTokenAsync(Acme, "acme-new-client");
        Assert.Equal(HttpStatusCode.OK, gained.StatusCode);
        Assert.Equal(Host + Acme, await IssuerOfTheAccessTokenAsync(gained));
    }

    /// <summary>
    /// A tenant removed while the server runs is no longer served on the next request, at any of its endpoints.
    /// </summary>
    [Fact]
    public async Task ATenantRemovedWhileTheServerRuns_IsNoLongerServed()
    {
        Assert.Equal(HttpStatusCode.OK, (await DiscoverAsync(Acme)).StatusCode);
        var stored = await StoredAsync("acme");

        AssertMade(await Manager.RemoveAsync("acme", stored.Version, TestContext.Current.CancellationToken));

        Assert.Equal(HttpStatusCode.NotFound, (await DiscoverAsync(Acme)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await RequestTokenAsync(Acme, AcmeClient)).StatusCode);
    }
}
