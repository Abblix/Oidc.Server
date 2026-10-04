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

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Two tenants with a client of the same id and secret, and a user signed in to both: what one tenant issued for the
/// user - an authorization code, an ID token naming the session - is honoured by no other.
/// </summary>
public sealed class SignedInTenantIsolationTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string ClientId = "shared-client-id";
    private const string ClientSecret = "shared-client-secret";
    private const string TokenPath = "/connect/token";
    private const string AuthorizePath = "/connect/authorize";
    private const string EndSessionPath = "/connect/endsession";
    private const string CodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri both tenants' clients register; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private WebApplication? _app;
    private HttpClient? _http;

    private HttpClient Http => _http!;

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton<IUserInfoProvider, SignedInUserInfo>();
        builder.Services.AddOidcServices(options => options.EnabledEndpoints = OidcEndpoints.Base);

        // The user is signed in and has consented, so the authorization endpoint answers with a code at once
        builder.Services.Replace(ServiceDescriptor.Singleton<IAuthSessionService, SignedInUser>());
        builder.Services.Replace(ServiceDescriptor.Singleton<IUserConsentsProvider, EverythingConsented>());

        builder.Services.AddMultiTenancy(options =>
        {
            options.Tenants.Add(Tenant("acme", Acme));
            options.Tenants.Add(Tenant("globex", Globex));
        });

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

    private static TenantDefinition Tenant(string id, string path) => new()
    {
        Id = id,
        Issuer = Host + path,
        Clients =
        [
            new ClientInfo(ClientId)
            {
                ClientSecrets =
                [
                    new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) },
                ],
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                AllowedGrantTypes = [GrantTypes.AuthorizationCode],
                RedirectUris = [new Uri(RedirectUri)],
                PostLogoutRedirectUris = [new Uri(RedirectUri)],
                PkceRequired = true,
            },
        ],
        LoginUri = new Uri("/login", UriKind.Relative),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    private static async Task<JsonNode> ReadJsonAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;

    /// <summary>
    /// The authorization code <paramref name="tenant"/> issues to the client for the signed-in user.
    /// </summary>
    private async Task<string> CodeAtAsync(string tenant)
    {
        var query = HttpUtility.ParseQueryString(string.Empty);
        query[AuthorizationRequest.Parameters.ClientId] = ClientId;
        query[AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code;
        query[AuthorizationRequest.Parameters.RedirectUri] = RedirectUri;
        query[AuthorizationRequest.Parameters.Scope] = Scopes.OpenId;
        query[AuthorizationRequest.Parameters.Nonce] = "nonce";
        query[AuthorizationRequest.Parameters.CodeChallenge] = CodeChallenge;
        query[AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256;

        var response = await Http.GetAsync($"{tenant}{AuthorizePath}?{query}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        return HttpUtility.ParseQueryString(response.Headers.Location!.Query)[ResponseParameters.Code]!;
    }

    private Task<HttpResponseMessage> RedeemAtAsync(string tenant, string code)
        => Http.PostAsync(
            tenant + TokenPath,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
                [TokenRequest.Parameters.Code] = code,
                [TokenRequest.Parameters.RedirectUri] = RedirectUri,
                [TokenRequest.Parameters.CodeVerifier] = CodeVerifier,
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
            TestContext.Current.CancellationToken);

    /// <summary>
    /// An authorization code one tenant issued is refused at the other, and still redeemed where it was issued.
    /// </summary>
    [Fact]
    public async Task AnAuthorizationCodeOfOneTenant_IsRefusedAtTheOther()
    {
        var code = await CodeAtAsync(Acme);

        var atGlobex = await RedeemAtAsync(Globex, code);
        Assert.Equal(HttpStatusCode.BadRequest, atGlobex.StatusCode);
        Assert.Equal(
            ErrorCodes.InvalidGrant,
            (await ReadJsonAsync(atGlobex))[ResponseParameters.Error]?.GetValue<string>());

        var atAcme = await RedeemAtAsync(Acme, code);
        Assert.Equal(HttpStatusCode.OK, atAcme.StatusCode);
    }

    /// <summary>
    /// An ID token one tenant issued is refused as the hint of a logout at the other, and accepted where it was issued.
    /// </summary>
    [Fact]
    public async Task AnIdTokenOfOneTenant_IsRefusedAsALogoutHintAtTheOther()
    {
        var tokens = await ReadJsonAsync(await RedeemAtAsync(Acme, await CodeAtAsync(Acme)));
        var idToken = tokens[ResponseParameters.IdToken]!.GetValue<string>();

        Task<HttpResponseMessage> EndSessionAtAsync(string tenant)
        {
            var query = HttpUtility.ParseQueryString(string.Empty);
            query[EndSessionRequest.Parameters.IdTokenHint] = idToken;
            query[EndSessionRequest.Parameters.PostLogoutRedirectUri] = RedirectUri;
            return Http.GetAsync($"{tenant}{EndSessionPath}?{query}", TestContext.Current.CancellationToken);
        }

        var atGlobex = await EndSessionAtAsync(Globex);
        Assert.Equal(HttpStatusCode.BadRequest, atGlobex.StatusCode);

        var atAcme = await EndSessionAtAsync(Acme);
        Assert.Equal(HttpStatusCode.Found, atAcme.StatusCode);
    }
}
