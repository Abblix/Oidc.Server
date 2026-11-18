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
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
#if MINIMAL_API_TRANSPORT
using Abblix.Oidc.Server.MinimalApi;
#else
using Abblix.Oidc.Server.Mvc;
#endif

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A host created from the plain web template, which registers no services of its own, answers the protocol
/// once it adds what the README leaves to it.
/// </summary>
public sealed class BareHostTests
{
    private const string Issuer = "https://auth.example.com";
    private const string ClientId = "bare-host-client";
    private const string ClientSecret = "bare-host-secret";

    /// <summary>
    /// Discovery and the token endpoint answer a host built like the README's quick-start, without a memory cache
    /// of the host's own.
    /// </summary>
    [Fact]
    public async Task AHostWithoutAMemoryCache_AnswersDiscoveryAndTheTokenEndpoint()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync(_ => { });
        var routes = app.Services.GetRequiredService<IOptions<OidcRouteOptions>>().Value;
        using var http = app.GetTestClient();
        http.BaseAddress = new Uri(Issuer);

        using var discovery = await http.GetAsync(routes.Configuration, ct);
        Assert.Equal(HttpStatusCode.OK, discovery.StatusCode);
        Assert.Equal(Issuer, (await ReadJsonAsync(discovery))[ConfigurationResponse.Parameters.Issuer]?.GetValue<string>());

        using var token = await http.PostAsync(
            routes.Token,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
            ct);
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        Assert.NotNull((await ReadJsonAsync(token))[TokenResponse.Parameters.AccessToken]?.GetValue<string>());
    }

    /// <summary>
    /// A memory cache the host registers before the server is the one the server uses.
    /// </summary>
    [Fact]
    public async Task AMemoryCacheOfTheHost_IsKept()
    {
        using var own = new MemoryCache(new MemoryCacheOptions());
        await using var app = await StartAsync(services => services.AddSingleton<IMemoryCache>(own));

        Assert.Same(own, app.Services.GetRequiredService<IMemoryCache>());
    }

    private static async Task<WebApplication> StartAsync(Action<IServiceCollection> ownServices)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        ownServices(builder.Services);

        // The README leaves the distributed cache to the host, since only it knows whether its instances share one
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "main",
            Issuer = new Uri(Issuer),
            LoginUri = new Uri("/Auth/Login", UriKind.Relative),
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
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
        }));

        var app = builder.Build();

        // Every protocol endpoint carries CORS metadata, and middleware is the host's to place
        app.UseCors();
#if MINIMAL_API_TRANSPORT
        app.MapOidcEndpoints();
#else
        app.MapOidcControllers();
#endif
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<JsonNode> ReadJsonAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
}
