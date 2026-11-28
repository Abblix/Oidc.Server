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
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A grant the token request itself authorizes has its scope judged before the grant is built, so a scope the client
/// may not have is refused without asking the host to check the end user's password: a host counting failed sign-ins
/// is not charged one by a request a corrected scope would let through.
/// </summary>
public sealed class PasswordGrantScopeOrderTests
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string TokenPath = "/connect/token";
    private const string ClientId = "password-client";
    private const string ClientSecret = "password-client-secret";

    /// <summary>
    /// A scope the tenant does not declare is refused as an invalid scope before the end user's credentials are
    /// checked, and the request naming a declared one has them checked once.
    /// </summary>
    [Fact]
    public async Task AScopeTheClientMayNotHave_IsRefusedBeforeTheCredentialsAreChecked()
    {
        var credentials = new CountingAuthenticator();
        await using var app = await StartAsync(credentials);

        using var refused = await PostGrantAsync(app, "not-declared");
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidScope, await ErrorResponseReader.ErrorCodeOf(refused));
        Assert.Equal(0, credentials.Checks);

        using var granted = await PostGrantAsync(app, Scopes.OpenId);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
        Assert.Equal(1, credentials.Checks);
    }

    private static async Task<WebApplication> StartAsync(CountingAuthenticator credentials)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddSingleton<IUserCredentialsAuthenticator>(credentials);
        builder.Services.EnablePasswordGrant();
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base;
            options.Tenants.Add(new TenantDefinition
            {
                Id = "acme",
                Issuer = new Uri(Host + Acme),
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
                        AllowedGrantTypes = [GrantTypes.Password],
                    },
                ],
            });
        });

        var app = builder.Build();
        app.UseMultiTenancy();
        app.UseCors();
        app.MapOidcEndpoints();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<HttpResponseMessage> PostGrantAsync(WebApplication app, string scope)
    {
        using var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.Password,
            [TokenRequest.Parameters.Username] = "user-1",
            [TokenRequest.Parameters.Password] = "any-password",
            [TokenRequest.Parameters.Scope] = scope,
            [ClientRequest.Parameters.ClientId] = ClientId,
            [ClientRequest.Parameters.ClientSecret] = ClientSecret,
        });
        return await http.PostAsync(Acme + TokenPath, content, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Takes every user name and password, counting the checks it is asked to make.
    /// </summary>
    private sealed class CountingAuthenticator : IUserCredentialsAuthenticator
    {
        private int _checks;

        public int Checks => _checks;

        public Task<Result<AuthorizedGrant, OidcError>> ValidateAsync(
            TenantDefinition tenant, string userName, string password, AuthorizationContext context)
        {
            Interlocked.Increment(ref _checks);
            return Task.FromResult<Result<AuthorizedGrant, OidcError>>(new AuthorizedGrant(
                new AuthSession(userName, "session-1", TimeProvider.System.GetUtcNow(), "local"),
                context));
        }
    }
}
