// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Abblix.Tests.Shared;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Distributed;
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
/// A host created from the plain web template, which registers no services of its own, answers the protocol with only
/// the CORS middleware added, and a cache the host does register is the one the server uses, whatever order the host
/// registers it in.
/// </summary>
public sealed class BareHostTests
{
    private const string TenantId = "main";
    private const string LoginPath = "/Auth/Login";
    private const string ClientId = "bare-host-client";
    private const string ClientSecret = "bare-host-secret";
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [SuppressMessage("Minor Code Smell", "S1075", Justification = "An address no fetch can reach; only the cache lookup before the fetch is observed.")]
    private const string KeySetAddress = "https://keys.example.invalid/jwks";

    /// <summary>
    /// Discovery, the token endpoint and the pushed authorization request endpoint, which stores the request, answer a
    /// host that registers neither a memory cache nor a distributed cache.
    /// </summary>
    [Fact]
    public async Task AHostWithoutCaches_AnswersTheProtocol()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync(_ => { }, _ => { });
        var routes = Routes(app);
        using var http = Client(app);

        using var discovery = await http.GetAsync(routes.Configuration, ct);
        Assert.Equal(HttpStatusCode.OK, discovery.StatusCode);
        var issuer = (await ReadJsonAsync(discovery))[ConfigurationResponse.Parameters.Issuer]?.GetValue<string>();
        Assert.NotNull(issuer);
        Assert.Equal(TestServerAddress.BaseAddress, new Uri(issuer));

        using var token = await RequestTokenAsync(http, routes);
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        Assert.NotNull((await ReadJsonAsync(token))[TokenResponse.Parameters.AccessToken]?.GetValue<string>());

        using var pushed = await PushAuthorizationRequestAsync(http, routes);
        Assert.Equal(HttpStatusCode.Created, pushed.StatusCode);
        Assert.NotNull((await ReadJsonAsync(pushed))[PushedAuthorizationResponse.Parameters.RequestUri]?.GetValue<string>());
    }

    /// <summary>
    /// The server stores in the distributed cache the host registered, in whichever order and by whichever method the
    /// host registered it.
    /// </summary>
    [Theory]
    [InlineData(HostRegistration.AddBefore)]
    [InlineData(HostRegistration.AddAfter)]
    [InlineData(HostRegistration.TryAddAfter)]
    public async Task ADistributedCacheOfTheHost_IsTheOneTheServerStoresIn(HostRegistration registration)
    {
        var own = new RecordingDistributedCache();
        await using var app = await StartAsync(
            registration.Before<IDistributedCache>(own),
            registration.After<IDistributedCache>(own));
        using var http = Client(app);

        using var pushed = await PushAuthorizationRequestAsync(http, Routes(app));

        Assert.Equal(HttpStatusCode.Created, pushed.StatusCode);
        Assert.NotEmpty(own.Written);
    }

    /// <summary>
    /// The server looks fetched documents up in the memory cache the host registered, in whichever order and by
    /// whichever method the host registered it.
    /// </summary>
    [Theory]
    [InlineData(HostRegistration.AddBefore)]
    [InlineData(HostRegistration.AddAfter)]
    [InlineData(HostRegistration.TryAddAfter)]
    public async Task AMemoryCacheOfTheHost_IsTheOneTheServerReads(HostRegistration registration)
    {
        using var own = new RecordingMemoryCache();
        await using var app = await StartAsync(
            registration.Before<IMemoryCache>(own),
            registration.After<IMemoryCache>(own));
        var fetcher = app.Services.GetRequiredKeyedService<ISecureHttpFetcher>(KeySetOwners.Client);

        await fetcher.FetchAsync<JsonWebKeySet>(new Uri(KeySetAddress));

        Assert.Contains(own.Read, key => key.EndsWith(KeySetAddress, StringComparison.Ordinal));
    }

    private static async Task<WebApplication> StartAsync(
        Action<IServiceCollection> beforeTheServer,
        Action<IServiceCollection> afterTheServer)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        beforeTheServer(builder.Services);
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(options => options.Tenants.Add(new TenantDefinition
        {
            Id = TenantId,
            Issuer = TestServerAddress.BaseAddress,
            LoginUri = new Uri(LoginPath, UriKind.Relative),
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
                    AllowedGrantTypes = [GrantTypes.ClientCredentials, GrantTypes.AuthorizationCode],
                    RedirectUris = [new Uri(TestConstants.RedirectUri)],
                },
            ],
        }));
        afterTheServer(builder.Services);

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

    private static OidcRouteOptions Routes(WebApplication app)
        => app.Services.GetRequiredService<IOptions<OidcRouteOptions>>().Value;

    private static HttpClient Client(WebApplication app)
    {
        var http = app.GetTestClient();
        http.BaseAddress = TestServerAddress.BaseAddress;
        return http;
    }

    private static Task<HttpResponseMessage> RequestTokenAsync(HttpClient http, OidcRouteOptions routes)
        => http.PostAsync(
            routes.Token,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
            TestContext.Current.CancellationToken);

    private static Task<HttpResponseMessage> PushAuthorizationRequestAsync(HttpClient http, OidcRouteOptions routes)
        => http.PostAsync(
            routes.PushedAuthorizationRequest,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
                [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
                [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
                [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
                [AuthorizationRequest.Parameters.CodeChallenge] = CodeChallenge,
                [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            }),
            TestContext.Current.CancellationToken);

    private static async Task<JsonNode> ReadJsonAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;

    /// <summary>
    /// A host's memory cache that records the keys looked up in it.
    /// </summary>
    private sealed class RecordingMemoryCache : IMemoryCache
    {
        private readonly MemoryCache _inner = new(new MemoryCacheOptions());

        public List<string> Read { get; } = [];

        public bool TryGetValue(object key, out object? value)
        {
            lock (Read) Read.Add(key.ToString() ?? string.Empty);
            return _inner.TryGetValue(key, out value);
        }

        public ICacheEntry CreateEntry(object key) => _inner.CreateEntry(key);

        public void Remove(object key) => _inner.Remove(key);

        public void Dispose() => _inner.Dispose();
    }
}
