// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// RFC 9701 section 5 refuses with 400 a request that does not "authenticate the caller", and what authenticates a
/// caller is decided by the authenticators, a host's own included: a resource server authenticating by a credential
/// the library knows nothing of is served, and a request no authenticator finds a credential in is still refused 400.
/// </summary>
public sealed class IntrospectionHostAuthenticatorTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string ClientId = "resource-server";

    /// <summary>
    /// The request header the host's authenticator reads its credential from, which no authenticator of the library
    /// reads.
    /// </summary>
    private const string ApiKeyHeader = "X-Resource-Server-Key";

    private const string ApiKey = "resource-server-key";

    /// <summary>
    /// A host's authenticator: the resource server is the caller presenting the shared key in its own header.
    /// </summary>
    private sealed class ApiKeyAuthenticator(IHttpContextAccessor httpContextAccessor) : IClientAuthenticator
    {
        public IEnumerable<string> ClientAuthenticationMethodsSupported => [];

        public Task<Result<ClientInfo, OidcError>> TryAuthenticateClientAsync(TenantDefinition tenant, ClientRequest request)
            => Task.FromResult(Authenticate(tenant));

        private Result<ClientInfo, OidcError> Authenticate(TenantDefinition tenant)
        {
            var headers = httpContextAccessor.HttpContext!.Request.Headers;

            // The host's own reading of "presented": its header, which no authenticator of the library reads
            if (!headers.TryGetValue(ApiKeyHeader, out var presented))
                return ClientAuthenticationFailures.NoCredential;

            if (presented != ApiKey)
                return ClientAuthenticationFailures.InvalidCredential;

            return tenant.Clients.First(client => client.ClientId == ClientId);
        }
    }

    private WebApplication? _app;
    private HttpClient? _http;

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddSingleton<IClientAuthenticator, ApiKeyAuthenticator>();
        builder.Services.AddIntrospection();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(options =>
            options.EnabledEndpoints = OidcEndpoints.Base | OidcEndpoints.Introspection);
        builder.Services.Configure<OidcOptions>(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri(Host + Acme),
            SigningKeys = [Abblix.Jwt.JsonWebKeyFactory.CreateRsa(Abblix.Jwt.PublicKeyUsages.Signature)],
            Clients =
            [
                new ClientInfo(ClientId)
                {
                    // A secret of its own as well, which these requests never present
                    ClientSecrets =
                    [
                        new ClientSecret
                        {
                            Sha512Hash = System.Security.Cryptography.SHA512.HashData("unused"u8.ToArray()),
                        },
                    ],
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                    AllowedGrantTypes = [GrantTypes.ClientCredentials],
                },
            ],
        }));

        _app = builder.Build();
        _app.UseMultiTenancy();
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

    private async Task<HttpResponseMessage> IntrospectAsync(string? apiKey)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, Acme + "/connect/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [IntrospectionRequest.Parameters.Token] = "any-token",
                [ClientRequest.Parameters.ClientId] = ClientId,
            }),
        };
        if (apiKey is not null)
            request.Headers.Add(ApiKeyHeader, apiKey);

        return await _http!.SendAsync(request, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The host's authenticator proves the caller from its header, so the request is served though it carries none of
    /// the credentials the library reads.
    /// </summary>
    [Fact]
    public async Task ACallerTheHostsAuthenticatorProves_IsServed()
    {
        Assert.Equal(HttpStatusCode.OK, (await IntrospectAsync(ApiKey)).StatusCode);
    }

    /// <summary>
    /// A wrong key in the host's header is a credential presented and refused, which RFC 7662 section 2.3 answers 401,
    /// not the 400 RFC 9701 section 5 has for a caller that presented none.
    /// </summary>
    [Fact]
    public async Task AWrongKeyInTheHostsHeader_Is401()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await IntrospectAsync("not-the-key")).StatusCode);
    }

    /// <summary>
    /// Without the header no authenticator finds a credential: 400.
    /// </summary>
    [Fact]
    public async Task ARequestNoAuthenticatorFindsACredentialIn_Is400()
    {
        Assert.Equal(HttpStatusCode.BadRequest, (await IntrospectAsync(apiKey: null)).StatusCode);
    }
}
