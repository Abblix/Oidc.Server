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
using System.Web;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A host declaring one tenant in its options, at an issuer without a path, serves it without calling
/// <c>UseMultiTenancy()</c>; every other host still needs the call and is told why it does not start without it.
/// </summary>
public sealed class SingleTenantWithoutTheCallTests
{
    private const string Host = "https://auth.example.com";

    private static readonly TimeSpan WhileTheLoadIsHeld = TimeSpan.FromSeconds(2);
    private const string ClientId = "single-tenant-client";
    private const string ClientSecret = "single-tenant-secret";
    private const string RedirectUri = "https://client.example.com/callback";
    private const string CodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

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
    /// A request arriving while the tenant is still being loaded at startup - the host starting its services at once,
    /// the tenant's preparation held open - waits for the load and is served, as on a host that calls the method.
    /// </summary>
    [Fact]
    public async Task ARequestDuringTheFirstLoad_WaitsForItAndIsServed()
    {
        var ct = TestContext.Current.CancellationToken;
        var preparation = new HeldPreparation();
        await using var app = Build([Tenant("acme", Host)], services =>
        {
            services.Configure<HostOptions>(host => host.ServicesStartConcurrently = true);
            services.AddSingleton<ITenantOpening>(preparation);
        });

        var start = app.StartAsync(ct);
        await preparation.Entered.Task.WaitAsync(ct);
        using var http = Client(app);
        var discovery = http.GetAsync("/.well-known/openid-configuration", ct);

        // Long enough for a request that does not wait to be answered while the load is still held open
        await Task.WhenAny(discovery, Task.Delay(WhileTheLoadIsHeld, ct));
        preparation.Release.SetResult();
        await start;

        using var response = await discovery;
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
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
    /// With the call in the pipeline, a reader of the tenant placed before it does not settle the request on the one
    /// tenant: a request on another host name still reaches no tenant.
    /// </summary>
    [Fact]
    public async Task WithTheCall_AReaderBeforeIt_DoesNotSettleTheTenant()
    {
        await using var app = await StartAsync([Tenant("acme", Host)], callsMultiTenancy: true, readsTenantFirst: true);
        using var http = app.GetTestClient();
        http.BaseAddress = new Uri("https://other.example.com");

        using var response = await http.GetAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// Without the call, a reader of the tenant placed before the host's path base does not settle the request on
    /// the one tenant: a request under the path base is still not served as it.
    /// </summary>
    [Fact]
    public async Task AReaderBeforeThePathBase_DoesNotSettleTheTenant()
    {
        await using var app = await StartAsync([Tenant("acme", Host)], pathBase: "/x", readsTenantFirst: true);
        using var http = Client(app);

        using var response = await http.GetAsync("/x/.well-known/openid-configuration", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// Without the call, an authorization code flow runs through the host's own sign-in: the host's login endpoint
    /// signs the user in, the authorization endpoint issues a code, and the token endpoint redeems it for an ID token
    /// carrying the configured issuer.
    /// </summary>
    [Fact]
    public async Task TheAuthorizationCodeFlow_RunsWithoutTheCall()
    {
        var ct = TestContext.Current.CancellationToken;
        await TestLicense.Loaded;
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton<IUserInfoProvider, SignedInUserInfo>();
        builder.Services.AddSingleton<IUserConsentsProvider, EverythingConsented>();
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base;
            options.Tenants.Add(Tenant("acme", Host));
        });
        await using var app = builder.Build();
        app.UseRouting();
        app.UseCors();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/login", async (IAuthSessionService sessions, TimeProvider clock) =>
        {
            await sessions.SignInAsync(new AuthSession("alice", "session-1", clock.GetUtcNow(), "local"));
            return Results.Ok();
        });
        app.MapOidcEndpoints();
        await app.StartAsync(ct);
        using var http = Client(app);

        using var login = await http.GetAsync("/login", ct);
        var cookie = string.Join("; ", login.Headers.GetValues("Set-Cookie").Select(header => header.Split(';')[0]));

        var query = HttpUtility.ParseQueryString(string.Empty);
        query[AuthorizationRequest.Parameters.ClientId] = ClientId;
        query[AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code;
        query[AuthorizationRequest.Parameters.RedirectUri] = RedirectUri;
        query[AuthorizationRequest.Parameters.Scope] = Scopes.OpenId;
        query[AuthorizationRequest.Parameters.Nonce] = "nonce";
        query[AuthorizationRequest.Parameters.CodeChallenge] = CodeChallenge;
        query[AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256;
        using var authorize = new HttpRequestMessage(HttpMethod.Get, $"/connect/authorize?{query}");
        authorize.Headers.Add(HeaderNames.Cookie, cookie);
        using var authorized = await http.SendAsync(authorize, ct);
        Assert.Equal(HttpStatusCode.SeeOther, authorized.StatusCode);
        var code = HttpUtility.ParseQueryString(authorized.Headers.Location!.Query)[ResponseParameters.Code];
        Assert.False(string.IsNullOrEmpty(code));

        using var token = await http.PostAsync(
            "/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
                [TokenRequest.Parameters.Code] = code!,
                [TokenRequest.Parameters.RedirectUri] = RedirectUri,
                [TokenRequest.Parameters.CodeVerifier] = CodeVerifier,
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
            ct);

        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        Assert.Equal(Host, IssuerOf((await ReadJsonAsync(token))[ResponseParameters.IdToken]!.GetValue<string>()));
    }

    /// <summary>
    /// A tenant whose issuer has a path, several tenants, and a store, store writer or catalog of the host's own each
    /// need the call, and a host leaving it out does not start, told so by name. Several tenants at the roots of
    /// hosts of their own are judged in <c>LoneTenantTests</c>, since the suite's license names one host.
    /// </summary>
    [Theory]
    [InlineData("path")]
    [InlineData("several")]
    [InlineData("store")]
    [InlineData("writer")]
    [InlineData("catalog")]
    public async Task AHostNeedingTheCall_DoesNotStartWithoutIt(string why)
    {
        TenantDefinition[] tenants = why switch
        {
            "path" => [Tenant("acme", Host + "/tenants/acme")],
            "several" => [Tenant("acme", Host + "/tenants/acme"), Tenant("globex", Host + "/tenants/globex")],
            "store" or "writer" or "catalog" => [Tenant("acme", Host)],
            _ => throw new ArgumentOutOfRangeException(nameof(why), why, null),
        };
        Action<IServiceCollection>? ownTenants = why switch
        {
            "store" => services => services.AddSingleton<ITenantStore, OwnStore>(),
            "writer" => services => services.AddSingleton<ITenantStoreWriter>(new MemoryTenantStore()),
            "catalog" => services => services.AddSingleton<ITenantCatalog>(
                provider => new OwnCatalog(provider.GetRequiredService<StoreTenantCatalog>())),
            _ => null,
        };
        var app = Build(tenants, ownTenants);

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
        bool callsMultiTenancy = false,
        bool readsTenantFirst = false)
    {
        var app = Build(
            tenants,
            pathBase: pathBase,
            callsMultiTenancy: callsMultiTenancy,
            readsTenantFirst: readsTenantFirst);
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static WebApplication Build(
        TenantDefinition[] tenants,
        Action<IServiceCollection>? ownTenants = null,
        string? pathBase = null,
        bool callsMultiTenancy = false,
        bool readsTenantFirst = false)
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

        ownTenants?.Invoke(builder.Services);

        var app = builder.Build();

        // A host's own middleware reading the tenant before anything has resolved the request, as a logging one may
        if (readsTenantFirst)
        {
            app.Use(async (context, next) =>
            {
                _ = context.RequestServices.GetRequiredService<ITenantAccessor>().Current;
                await next(context);
            });
        }

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
        LoginUri = new Uri("/login", UriKind.Relative),
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
                RedirectUris = [new Uri(RedirectUri)],
                PkceRequired = true,
            },
        ],
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    /// <summary>
    /// A preparation of the tenants that holds the load open until the test releases it, as one fetching a key from a
    /// vault does until the vault answers.
    /// </summary>
    private sealed class HeldPreparation : ITenantOpening
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
            IReadOnlyCollection<TenantDefinition> tenants,
            CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            await Release.Task;
            return new Dictionary<string, Exception>();
        }
    }

    /// <summary>
    /// A read-only tenant store of the host's own, as a host keeping its tenants in a database registers.
    /// </summary>
    private sealed class OwnStore(IOptions<OidcOptions> options) : ITenantStore
    {
        private readonly OptionsTenantStore _declared = new(options);

        public Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
            => _declared.ListAsync(cancellationToken);
    }

    /// <summary>
    /// A tenant catalog of the host's own over the server's, as a logging or caching decorator is.
    /// </summary>
    private sealed class OwnCatalog(StoreTenantCatalog served) : ITenantCatalog
    {
        public ValueTask<TenantDefinition?> FindByIdAsync(string tenantId, CancellationToken cancellationToken)
            => served.FindByIdAsync(tenantId, cancellationToken);

        public ValueTask<TenantDefinition?> FindByAddressAsync(string host, string path, CancellationToken cancellationToken)
            => served.FindByAddressAsync(host, path, cancellationToken);
    }

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
