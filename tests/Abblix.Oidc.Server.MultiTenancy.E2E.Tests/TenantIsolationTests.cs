// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Two tenants served by one running server, each with a client of the same id and the same secret, so nothing
/// but the tenant tells their requests apart: what one tenant issued must not be honoured by the other.
/// </summary>
public sealed class TenantIsolationTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string ClientId = "shared-client-id";
    private const string ClientSecret = "shared-client-secret";
    private const string RedirectUri = "https://client.example.com/callback";

    private WebApplication? _app;
    private HttpClient? _http;

    private HttpClient Http => _http!;

    public async ValueTask InitializeAsync()
    {
        await License.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        // What a host supplies to the server: a cache for its storage, a cookie scheme for the signed-in user.
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton<IUserInfoProvider, NoUserInfoProvider>();

        // Grant features before AddOidcServices, which composes the grant handlers.
        builder.Services.AddDeviceAuthorization();
        builder.Services.AddOidcServices(options =>
        {
            options.LoginUri = new Uri("/login", UriKind.Relative);
            options.DeviceAuthorization = new DeviceAuthorizationOptions
            {
                VerificationUri = new Uri(Host + "/device"),
                CodeLifetime = TimeSpan.FromMinutes(15),
                PollingInterval = TimeSpan.FromSeconds(5),
                DeviceCodeLength = 32,
                UserCodeLength = 8,
            };
            options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)];
            options.Clients =
            [
                new ClientInfo(ClientId)
                {
                    ClientSecrets = [new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) }],
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                    AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.DeviceAuthorization],
                    RedirectUris = [new Uri(RedirectUri)],
                    PkceRequired = true,
                },
            ];
        });
        builder.Services.AddMultiTenancy(options =>
        {
            options.Tenants.Add(new TenantDefinition { Id = "acme", Issuer = Host + Acme });
            options.Tenants.Add(new TenantDefinition { Id = "globex", Issuer = Host + Globex });
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

    private Task<HttpResponseMessage> PostAsync(string tenant, string path, Dictionary<string, string> form)
    {
        form[ClientRequest.Parameters.ClientId] = ClientId;
        form[ClientRequest.Parameters.ClientSecret] = ClientSecret;
        return Http.PostAsync(tenant + path, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);
    }

    private static async Task<JsonNode> ReadJsonAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;

    /// <summary>
    /// A pushed authorization request registered with one tenant is not found by the other: its request_uri
    /// names a request the other tenant never received.
    /// </summary>
    [Fact]
    public async Task APushedRequestOfOneTenant_IsUnknownToTheOther()
    {
        var pushed = await PostAsync(Acme, "/connect/par", new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = "openid",
            [AuthorizationRequest.Parameters.CodeChallenge] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = "S256",
        });
        Assert.Equal(HttpStatusCode.Created, pushed.StatusCode);
        var requestUri = (await ReadJsonAsync(pushed))[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();

        var query = $"/connect/authorize?client_id={ClientId}&request_uri={Uri.EscapeDataString(requestUri)}";

        var atGlobex = await Http.GetAsync(Globex + query, TestContext.Current.CancellationToken);
        var globexAnswer = atGlobex.Headers.Location?.ToString()
                           ?? await atGlobex.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains(ErrorCodes.InvalidRequestUri, globexAnswer, StringComparison.Ordinal);

        // 303 rather than 302: the authorization endpoint also accepts POST, whose body may carry the user's
        // credentials, and 303 makes the user agent follow with a GET that never re-sends that body. RFC 9700
        // section 4.12: such a server "MUST NOT use the HTTP 307" and "SHOULD use HTTP status code 303 (See Other)".
        var atAcme = await Http.GetAsync(Acme + query, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.SeeOther, atAcme.StatusCode);
        Assert.StartsWith(Host + Acme + "/login", atAcme.Headers.Location?.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A device code one tenant issued is unknown at the other tenant's token endpoint, and still pending at its own.
    /// </summary>
    [Fact]
    public async Task ADeviceCodeOfOneTenant_IsUnknownToTheOther()
    {
        var authorization = await PostAsync(Acme, "/connect/deviceauthorization", new Dictionary<string, string>
        {
            [DeviceAuthorizationRequest.Parameters.Scope] = "openid",
        });
        Assert.Equal(HttpStatusCode.OK, authorization.StatusCode);
        var deviceCode = (await ReadJsonAsync(authorization))[DeviceAuthorizationResponse.Parameters.DeviceCode]!.GetValue<string>();

        var poll = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.DeviceAuthorization,
            [TokenRequest.Parameters.DeviceCode] = deviceCode,
        };

        var atGlobex = await PostAsync(Globex, "/connect/token", new Dictionary<string, string>(poll));
        Assert.Equal(ErrorCodes.InvalidGrant, (await ReadJsonAsync(atGlobex))[ResponseParameters.Error]?.GetValue<string>());

        var atAcme = await PostAsync(Acme, "/connect/token", new Dictionary<string, string>(poll));
        Assert.Equal(ErrorCodes.AuthorizationPending, (await ReadJsonAsync(atAcme))[ResponseParameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// The license this process runs under: the multi-tenant test license, which names both tenants' issuers.
    /// </summary>
    private static class License
    {
        public static readonly Task Loaded = LoadAsync();

        private static async Task LoadAsync()
        {
            var assembly = Assembly.GetExecutingAssembly();
            const string name = "Abblix.Oidc.Server.MultiTenancy.E2E.Tests.Resources.test-license-multitenant.jwt";
            await using var stream = assembly.GetManifestResourceStream(name)
                ?? throw new InvalidOperationException($"The embedded license {name} is missing.");
            using var reader = new StreamReader(stream);
            await LicenseLoader.LoadAsync((await reader.ReadToEndAsync()).Trim());
        }
    }
}
