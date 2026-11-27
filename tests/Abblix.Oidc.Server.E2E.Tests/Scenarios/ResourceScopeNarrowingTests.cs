// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A token request naming a scope only a resource declares is narrowed by it as by any other scope: the token carries
/// what the request names within its grant (RFC 6749 section 6), whatever the grant type.
/// </summary>
public class ResourceScopeNarrowingTests(TestFactory factory) : TestBase(factory)
{
    private const string GrantedScope = $"{Scopes.OpenId} {Scopes.OfflineAccess} {TestConstants.ApiScope}";

    /// <summary>
    /// A refresh naming the resource's scope beside offline access keeps both, as a client refreshing the scope it
    /// was granted expects.
    /// </summary>
    [Fact]
    public async Task A_refresh_naming_a_resource_scope_keeps_it()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var refreshToken = await ObtainRefreshTokenAsync(client, discovery, GrantedScope);

        var tokens = await ExchangeCodeForTokensAsync(
            client,
            discovery,
            RefreshForm(refreshToken, $"{TestConstants.ApiScope} {Scopes.OfflineAccess}"));

        AssertIssuedScope([TestConstants.ApiScope, Scopes.OfflineAccess], tokens);
    }

    /// <summary>
    /// A refresh naming the resource's scope alone narrows the grant to it.
    /// </summary>
    [Fact]
    public async Task A_refresh_naming_only_a_resource_scope_is_narrowed_to_it()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var refreshToken = await ObtainRefreshTokenAsync(client, discovery, GrantedScope);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, RefreshForm(refreshToken, TestConstants.ApiScope));

        AssertIssuedScope([TestConstants.ApiScope], tokens);
    }

    /// <summary>
    /// A refresh naming only a resource's scope its grant does not hold is refused as not granted, as a tenant scope
    /// outside the grant is.
    /// </summary>
    [Fact]
    public async Task A_refresh_naming_a_resource_scope_outside_its_grant_is_refused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var refreshToken = await ObtainRefreshTokenAsync(client, discovery, $"{Scopes.OpenId} {Scopes.OfflineAccess}");

        using var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            RefreshForm(refreshToken, TestConstants.ApiScope));
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"expected 400, got {(int)response.StatusCode}: {body}");
        Assert.Equal(ErrorCodes.InvalidScope, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// A code redemption naming the resource's scope beside a tenant scope keeps both.
    /// </summary>
    [Fact]
    public async Task A_code_redemption_naming_a_resource_scope_keeps_it()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (code, verifier) = await AuthorizeAsync(client, discovery, GrantedScope);

        var tokens = await ExchangeCodeForTokensAsync(
            client,
            discovery,
            [
                .. RedeemForm(code, verifier),
                new(TokenRequest.Parameters.Scope, $"{Scopes.OpenId} {TestConstants.ApiScope}"),
                new(TokenRequest.Parameters.Resource, TestConstants.ApiResource),
            ]);

        AssertIssuedScope([Scopes.OpenId, TestConstants.ApiScope], tokens);
    }

    /// <summary>
    /// A client credentials request naming the resource's scope beside a tenant scope is issued both.
    /// </summary>
    [Fact]
    public async Task A_client_credentials_request_naming_a_resource_scope_keeps_it()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [ClientRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.Scope] = $"{Scopes.Profile} {TestConstants.ApiScope}",
            [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
        });

        AssertIssuedScope([Scopes.Profile, TestConstants.ApiScope], tokens);
    }

    /// <summary>
    /// A token exchange naming the resource's scope beside a tenant scope, both held by the subject token, keeps both.
    /// </summary>
    [Fact]
    public async Task A_token_exchange_naming_a_resource_scope_keeps_it()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var refreshToken = await ObtainRefreshTokenAsync(client, discovery, GrantedScope);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.TokenExchange,
            [TokenRequest.Parameters.SubjectToken] = refreshToken,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.RefreshToken,
            [TokenRequest.Parameters.Scope] = $"{Scopes.OpenId} {TestConstants.ApiScope}",
            [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        AssertIssuedScope([Scopes.OpenId, TestConstants.ApiScope], tokens);
    }

    private static async Task<string> ObtainRefreshTokenAsync(HttpClient client, DiscoveryDocument discovery, string scope)
    {
        var (code, verifier) = await AuthorizeAsync(client, discovery, scope);
        var tokens = await ExchangeCodeForTokensAsync(client, discovery, RedeemForm(code, verifier));
        return tokens[TokenResponse.Parameters.RefreshToken]!.GetValue<string>();
    }

    private static async Task<(string Code, string Verifier)> AuthorizeAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string scope)
    {
        var (verifier, challenge) = GeneratePkcePair();
        var parameters = CodeFlowParameters(TestConstants.ConfidentialClientId, challenge);
        parameters[AuthorizationRequest.Parameters.Scope] = scope;
        parameters[AuthorizationRequest.Parameters.Resource] = TestConstants.ApiResource;
        return (await AuthorizeAndExtractCodeAsync(client, discovery, parameters), verifier);
    }

    private static KeyValuePair<string, string>[] RedeemForm(string code, string verifier) =>
    [
        new(TokenRequest.Parameters.GrantType, GrantTypes.AuthorizationCode),
        new(TokenRequest.Parameters.Code, code),
        new(TokenRequest.Parameters.RedirectUri, TestConstants.RedirectUri),
        new(TokenRequest.Parameters.CodeVerifier, verifier),
        new(ClientRequest.Parameters.ClientId, TestConstants.ConfidentialClientId),
        new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
    ];

    private static KeyValuePair<string, string>[] RefreshForm(string refreshToken, string scope) =>
    [
        new(TokenRequest.Parameters.GrantType, GrantTypes.RefreshToken),
        new(TokenRequest.Parameters.RefreshToken, refreshToken),
        new(TokenRequest.Parameters.Scope, scope),
        new(TokenRequest.Parameters.Resource, TestConstants.ApiResource),
        new(ClientRequest.Parameters.ClientId, TestConstants.ConfidentialClientId),
        new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
    ];

    private static void AssertIssuedScope(string[] expected, JsonObject tokens)
    {
        var payload = DecodeJwtPayload(tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>());
        var carried = payload[IanaClaimTypes.Scope]?.GetValue<string>().Split(' ') ?? [];

        Assert.Equal(expected.Order(StringComparer.Ordinal), carried.Order(StringComparer.Ordinal));
    }
}
