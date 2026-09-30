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
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Each tenant holds its clients to the security profile it declares, and no other tenant's.
/// </summary>
/// <remarks>
/// A server of its own rather than the isolation suite's, because a strict profile refuses the plain client that
/// suite relies on at every tenant that declares it. That refusal comes at startup for a client a tenant declares,
/// so the client here reaches the strict tenant the way a stored registration does: added after the server
/// starts, as one registered dynamically before the profile was put in force.
/// </remarks>
public sealed class TenantSecurityProfileTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string ClientId = "shared-client-id";
    private const string ClientSecret = "shared-client-secret";
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri both tenants' clients register; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private static readonly TenantDefinition GlobexTenant = new()
    {
        Id = "globex",
        Issuer = Host + Globex,
        DefaultSecurityProfile = ClientSecurityProfile.Fapi2,
    };

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
        builder.Services.AddSingleton<IUserInfoProvider, NoUserInfoProvider>();
        builder.Services.AddOidcServices(options =>
            options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)]);
        builder.Services.AddMultiTenancy(options =>
        {
            options.Tenants.Add(new TenantDefinition { Id = "acme", Issuer = Host + Acme, Clients = [Client()] });
            options.Tenants.Add(GlobexTenant);
        });

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseAuthorization();
        _app.MapOidcEndpoints();
        await _app.StartAsync(TestContext.Current.CancellationToken);

        using (TenantScope.Enter(GlobexTenant))
            Assert.True(await _app.Services.GetRequiredService<IClientInfoManager>()
                .TryAddClientAsync(new RegisteredClient(Client(), "registration-access-token-id")));

        _http = _app.GetTestClient();
        _http.BaseAddress = new Uri(Host);
    }

    public async ValueTask DisposeAsync()
    {
        _http?.Dispose();
        if (_app is not null)
            await _app.DisposeAsync();
    }

    private static ClientInfo Client() => new(ClientId)
    {
        ClientSecrets = [new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) }],
        TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
        AllowedGrantTypes = [GrantTypes.AuthorizationCode],
        RedirectUris = [new Uri(RedirectUri)],
        PkceRequired = true,
    };

    /// <summary>
    /// A client authenticating with a shared secret is let in at the tenant without a profile, and refused at the
    /// tenant holding its clients to FAPI 2.0, which admits only a private key or a certificate.
    /// </summary>
    [Fact]
    public async Task AStrictProfile_BindsOnlyTheTenantThatDeclaresIt()
    {
        Task<HttpResponseMessage> PushAsync(string tenant) => _http!.PostAsync(
            tenant + "/connect/par",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
                [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
                [AuthorizationRequest.Parameters.RedirectUri] = RedirectUri,
                [AuthorizationRequest.Parameters.Scope] = "openid",
                [AuthorizationRequest.Parameters.CodeChallenge] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                [AuthorizationRequest.Parameters.CodeChallengeMethod] = "S256",
            }),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, (await PushAsync(Acme)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await PushAsync(Globex)).StatusCode);
    }
}
