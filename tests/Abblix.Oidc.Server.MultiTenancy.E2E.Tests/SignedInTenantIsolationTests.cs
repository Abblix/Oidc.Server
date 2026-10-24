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


namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Two tenants with a client of the same id and secret, and a user signed in to both: what one tenant issued for the
/// user - an authorization code, an ID token naming the session - is honoured by no other.
/// </summary>
public sealed class SignedInTenantIsolationTests : IAsyncLifetime
{
    private const string Acme = SignedInTenantsHost.Acme;
    private const string Globex = SignedInTenantsHost.Globex;
    private const string ClientSecret = "shared-client-secret";
    private const string TokenPath = "/connect/token";
    private const string EndSessionPath = "/connect/endsession";
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri both tenants' clients register; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private SignedInTenantsHost? _host;

    private HttpClient Http => _host!.Http;

    public async ValueTask InitializeAsync()
        => _host = await SignedInTenantsHost.StartAsync(_ => new ClientInfo(SignedInTenantsHost.ClientId)
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
        });

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
            await _host.DisposeAsync();
    }

    private static async Task<JsonNode> ReadJsonAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;

    private Task<string> CodeAtAsync(string tenant) => _host!.CodeAtAsync(tenant, RedirectUri);

    private Task<HttpResponseMessage> RedeemAtAsync(string tenant, string code)
        => Http.PostAsync(
            tenant + TokenPath,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
                [TokenRequest.Parameters.Code] = code,
                [TokenRequest.Parameters.RedirectUri] = RedirectUri,
                [TokenRequest.Parameters.CodeVerifier] = SignedInTenantsHost.CodeVerifier,
                [ClientRequest.Parameters.ClientId] = SignedInTenantsHost.ClientId,
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
