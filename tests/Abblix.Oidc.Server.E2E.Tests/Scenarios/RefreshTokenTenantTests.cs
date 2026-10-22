// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A refresh token names the tenant and creation it was issued at, and every endpoint reading one back accepts it
/// only there. A token naming none, as every refresh token issued before 3.0, is made here by re-signing a genuine
/// one with the tenant's own key without that claim, so a refusal is about the claim alone; the same token
/// re-signed unchanged is the control that proves the re-signing keeps it acceptable.
/// </summary>
public class RefreshTokenTenantTests(TestFactory factory) : TestBase(factory)
{
    // The claim the server names the tenant under, which this project cannot reference
    private const string TenantClaim = "abblix_tenant";
    private const string ErrorMember = "error";

    private static readonly IServiceProvider JwtServices = BuildJwtServices();

    private static ServiceProvider BuildJwtServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// A refresh token re-signed unchanged is renewed, and the renewed one names the tenant again.
    /// </summary>
    [Fact]
    public async Task ARefreshTokenNamingTheTenant_IsRenewed_AndTheRenewedOneNamesIt()
    {
        var (client, discovery, tokens) = await GenuineAsync();

        var (status, body) = await RefreshAsync(client, discovery, await ResignAsync(RefreshTokenOf(tokens), _ => { }));

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(TestTenantSettings.TenantId, DecodeJwtPayload(RefreshTokenOf(body!))[TenantClaim]!.GetValue<string>());
    }

    /// <summary>
    /// The token endpoint refuses to renew a refresh token naming no tenant.
    /// </summary>
    [Fact]
    public async Task ARefreshTokenNamingNoTenant_IsNotRenewed()
    {
        var (client, discovery, tokens) = await GenuineAsync();

        var (status, body) = await RefreshAsync(client, discovery, await WithoutTenantAsync(tokens));

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(ErrorCodes.InvalidGrant, body![ErrorMember]!.GetValue<string>());
    }

    /// <summary>
    /// A refresh token naming no tenant is an invalid subject token for the token exchange, while the same token
    /// naming it is exchanged.
    /// </summary>
    [Fact]
    public async Task ARefreshTokenNamingNoTenant_IsNotExchanged()
    {
        var (client, discovery, tokens) = await GenuineAsync();

        var (controlStatus, _) = await ExchangeAsync(
            client, discovery, await ResignAsync(RefreshTokenOf(tokens), _ => { }));
        var (status, body) = await ExchangeAsync(client, discovery, await WithoutTenantAsync(tokens));

        Assert.Equal(HttpStatusCode.OK, controlStatus);
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(ErrorCodes.InvalidRequest, body![ErrorMember]!.GetValue<string>());
    }

    /// <summary>
    /// A refresh token naming no tenant is introspected as inactive, while the same token naming it is active.
    /// </summary>
    [Fact]
    public async Task ARefreshTokenNamingNoTenant_IsIntrospectedAsInactive()
    {
        var (client, discovery, tokens) = await GenuineAsync();

        var control = await IntrospectAsync(
            client,
            discovery,
            await ResignAsync(RefreshTokenOf(tokens), _ => { }),
            TestConstants.ConfidentialClientId);
        var withoutTenant = await IntrospectAsync(
            client,
            discovery,
            await WithoutTenantAsync(tokens),
            TestConstants.ConfidentialClientId);

        Assert.True(control[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
        Assert.False(withoutTenant[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
    }

    /// <summary>
    /// Revoking a refresh token naming no tenant records nothing, so the genuine token sharing its id still renews;
    /// revoking the same token naming the tenant does stop it.
    /// </summary>
    [Theory]
    [InlineData(false, HttpStatusCode.OK)]
    [InlineData(true, HttpStatusCode.BadRequest)]
    public async Task RevokingARefreshToken_StopsItsGrant_OnlyWhenItNamesTheTenant(
        bool namesTheTenant,
        HttpStatusCode renewal)
    {
        var (client, discovery, tokens) = await GenuineAsync();
        var revoked = namesTheTenant
            ? await ResignAsync(RefreshTokenOf(tokens), _ => { })
            : await WithoutTenantAsync(tokens);

        var (revocation, _) = await PostAsync(client, discovery.RevocationEndpoint!, new()
        {
            [RevocationRequest.Parameters.Token] = revoked,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });
        var (status, _) = await RefreshAsync(client, discovery, RefreshTokenOf(tokens));

        Assert.Equal(HttpStatusCode.OK, revocation);
        Assert.Equal(renewal, status);
    }

    /// <summary>
    /// The tenant a refresh token names stays in it: the access token issued for it carries no such claim to a
    /// resource server, as the access token of the sign-in carries none.
    /// </summary>
    [Fact]
    public async Task TheAccessTokenIssuedForARefreshToken_DoesNotNameTheTenant()
    {
        var (client, discovery, tokens) = await GenuineAsync();

        var (status, body) = await RefreshAsync(client, discovery, RefreshTokenOf(tokens));
        var accessToken = body![UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var introspected = await IntrospectAsync(client, discovery, accessToken, TestConstants.ConfidentialClientId);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Null(DecodeJwtPayload(accessToken)[TenantClaim]);
        Assert.Null(introspected[TenantClaim]);
    }

    /// <summary>
    /// At a tenant created again, a refresh token naming the tenant without its creation is not renewed, while the one
    /// issued there, naming both, is.
    /// </summary>
    [Fact]
    public async Task AtATenantCreatedAgain_ARefreshTokenNamingTheTenantAlone_IsNotRenewed()
    {
        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.PostConfigure<TestTenantSettings>(tenant => tenant.Generation = "g7")));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);
        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);

        var tenantAlone = await ResignAsync(
            RefreshTokenOf(tokens),
            payload => payload[TenantClaim] = TestTenantSettings.TenantId,
            host.Services);
        var (refused, body) = await RefreshAsync(client, discovery, tenantAlone);
        var (renewed, _) = await RefreshAsync(client, discovery, RefreshTokenOf(tokens));

        Assert.Equal(HttpStatusCode.BadRequest, refused);
        Assert.Equal(ErrorCodes.InvalidGrant, body![ErrorMember]!.GetValue<string>());
        Assert.Equal(HttpStatusCode.OK, renewed);
    }

    private async Task<(HttpClient Client, DiscoveryDocument Discovery, JsonObject Tokens)> GenuineAsync()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        return (client, discovery, tokens);
    }

    private static string RefreshTokenOf(JsonObject tokens)
        => tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

    private Task<string> WithoutTenantAsync(JsonObject tokens)
        => ResignAsync(RefreshTokenOf(tokens), payload => payload.Remove(TenantClaim));

    private async Task<string> ResignAsync(string jwt, Action<JsonObject> edit, IServiceProvider? host = null)
    {
        var parts = jwt.Split('.');
        var header = JsonNode.Parse(Encoding.UTF8.GetString(Base64UrlDecode(parts[0])))!.AsObject();
        var payload = JsonNode.Parse(Encoding.UTF8.GetString(Base64UrlDecode(parts[1])))!.AsObject();
        edit(payload);

        var key = (host ?? Factory.Services).GetRequiredService<IOptions<TestTenantSettings>>().Value.SigningKeys.First();
        var token = new JsonWebToken
        {
            Header = new JsonWebTokenHeader(header),
            Payload = new JsonWebTokenPayload(payload),
        };
        return await JwtServices.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, key);
    }

    private static Task<(HttpStatusCode, JsonObject?)> RefreshAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string refreshToken)
        => PostAsync(client, discovery.TokenEndpoint, new()
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

    private static Task<(HttpStatusCode, JsonObject?)> ExchangeAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string refreshToken)
        => PostAsync(client, discovery.TokenEndpoint, new()
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.TokenExchange,
            [TokenRequest.Parameters.SubjectToken] = refreshToken,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.RefreshToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

    private static async Task<(HttpStatusCode, JsonObject?)> PostAsync(
        HttpClient client,
        Uri uri,
        Dictionary<string, string> form)
    {
        var response = await FormPostHelpers.PostFormAsync(client, uri, form);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return (response.StatusCode, raw.Length == 0 ? null : JsonNode.Parse(raw)?.AsObject());
    }
}
