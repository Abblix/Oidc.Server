// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Web;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A server serving two tenants under paths of one host, each registering a client under the same id, with a user
/// signed in to both who has consented to everything, so the authorization endpoint answers with a code at once.
/// </summary>
internal sealed class SignedInTenantsHost : IAsyncDisposable
{
    public const string Host = "https://auth.example.com";
    public const string Acme = "/tenants/acme";
    public const string Globex = "/tenants/globex";
    public const string ClientId = "shared-client-id";
    public const string CodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string AuthorizePath = "/connect/authorize";

    private readonly WebApplication _app;

    private SignedInTenantsHost(WebApplication app, HttpClient http)
    {
        _app = app;
        Http = http;
    }

    public HttpClient Http { get; }

    /// <summary>
    /// Starts the server, with the client each tenant registers built by <paramref name="clientOf"/> from the tenant's
    /// id, and the host's own services added by <paramref name="configure"/>.
    /// </summary>
    public static async Task<SignedInTenantsHost> StartAsync(
        Func<string, ClientInfo> clientOf,
        Action<IServiceCollection>? configure = null)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton<IUserInfoProvider, SignedInUserInfo>();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(options => options.EnabledEndpoints = OidcEndpoints.Base);
        builder.Services.Replace(ServiceDescriptor.Singleton<IAuthSessionService, SignedInUser>());
        builder.Services.Replace(ServiceDescriptor.Singleton<IUserConsentsProvider, EverythingConsented>());
        configure?.Invoke(builder.Services);

        builder.Services.Configure<OidcOptions>(options =>
        {
            options.Tenants.Add(Tenant("acme", Acme, clientOf("acme")));
            options.Tenants.Add(Tenant("globex", Globex, clientOf("globex")));
        });

        var app = builder.Build();
        app.UseMultiTenancy();
        app.UseCors();
        app.UseAuthorization();
        app.MapOidcEndpoints();

        await app.StartAsync(TestContext.Current.CancellationToken);

        var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);
        return new SignedInTenantsHost(app, http);
    }

    private static TenantDefinition Tenant(string id, string path, ClientInfo client) => new()
    {
        Id = id,
        Issuer = new Uri(Host + path),
        Clients = [client],
        LoginUri = new Uri("/login", UriKind.Relative),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    /// <summary>
    /// Asks <paramref name="tenant"/> to authorize its client for the signed-in user, which also puts the client among
    /// those a logout of the user's session there notifies.
    /// </summary>
    public Task<HttpResponseMessage> AuthorizeAtAsync(string tenant, string redirectUri)
    {
        var query = HttpUtility.ParseQueryString(string.Empty);
        query[AuthorizationRequest.Parameters.ClientId] = ClientId;
        query[AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code;
        query[AuthorizationRequest.Parameters.RedirectUri] = redirectUri;
        query[AuthorizationRequest.Parameters.Scope] = Scopes.OpenId;
        query[AuthorizationRequest.Parameters.Nonce] = "nonce";
        query[AuthorizationRequest.Parameters.CodeChallenge] = CodeChallenge;
        query[AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256;

        return Http.GetAsync($"{tenant}{AuthorizePath}?{query}", TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The authorization code <paramref name="tenant"/> issues to its client for the signed-in user.
    /// </summary>
    public async Task<string> CodeAtAsync(string tenant, string redirectUri)
    {
        using var response = await AuthorizeAtAsync(tenant, redirectUri);
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        return HttpUtility.ParseQueryString(response.Headers.Location!.Query)[ResponseParameters.Code]!;
    }

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        await _app.DisposeAsync();
    }
}
