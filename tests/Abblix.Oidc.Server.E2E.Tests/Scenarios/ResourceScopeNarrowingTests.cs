// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A token request naming a scope only a resource declares is narrowed by it as by any other scope: the token carries
/// what the request names within its grant (RFC 6749 section 6). A grant authorized earlier speaks for the resources it
/// holds when the request names none (RFC 8707 section 2.2); a grant the request itself authorizes speaks for the
/// ones it names.
/// </summary>
public class ResourceScopeNarrowingTests(TestFactory factory) : TestBase(factory)
{
    public const string Code = "code";
    public const string Refresh = "refresh";
    public const string Exchange = "exchange";
    public const string ClientCredentials = "client_credentials";

    /// <summary>The request names the scope only the resource declares.</summary>
    public const string ResourceScope = "resource";

    /// <summary>The request names a scope the tenant declares.</summary>
    public const string TenantScope = "tenant";

    /// <summary>The request names both.</summary>
    public const string BothScopes = "both";

    private const string GrantedScope = $"{Scopes.OpenId} {Scopes.OfflineAccess} {TestConstants.ApiScope}";

    public static TheoryData<string, string, bool> Matrix()
    {
        var rows =
            from grant in new[] { Code, Refresh, Exchange, ClientCredentials }
            from named in new[] { ResourceScope, TenantScope, BothScopes }
            from namesResource in new[] { true, false }
            select (grant, named, namesResource);
        return new TheoryData<string, string, bool>(rows);
    }

    /// <summary>The request names a scope nobody declares.</summary>
    public const string UnknownScope = "unknown";

    /// <summary>
    /// Every kind of scope named, one nobody declares included, with the resource named or not, for a grant whose
    /// token request defines no scope and so is issued its grant whatever it names.
    /// </summary>
    public static TheoryData<string, bool> IgnoredRows() => new(
        from named in new[] { ResourceScope, TenantScope, BothScopes, UnknownScope }
        from namesResource in new[] { true, false }
        select (named, namesResource));

    /// <summary>
    /// Each grant type served here, asked for the resource's scope, a tenant scope or both, with the resource named
    /// or not: the token carries what was named, or, where no resource the request speaks for declares the scope,
    /// the request is refused as asking for a scope that is not available.
    /// </summary>
    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task A_token_request_is_issued_the_scope_it_names(string grant, string named, bool namesResource)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var tenantScope = grant == ClientCredentials ? Scopes.Profile : Scopes.OpenId;
        var requested = Requested(named, tenantScope);

        using var response = await RequestAsync(client, discovery, grant, string.Join(' ', requested), namesResource);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

        if (IsRefused(grant, named, namesResource))
        {
            Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"expected 400, got {(int)response.StatusCode}: {body}");
            Assert.Equal(ErrorCodes.InvalidScope, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
            return;
        }

        Assert.True(response.StatusCode == HttpStatusCode.OK, $"expected 200, got {(int)response.StatusCode}: {body}");
        AssertIssuedScope(requested, body);
    }

    /// <summary>
    /// A refresh naming only a resource's scope its grant does not hold is refused as not granted, as a tenant scope
    /// outside the grant is, whether the request names the resource or not.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_refresh_naming_a_resource_scope_outside_its_grant_is_refused(bool namesResource)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var refreshToken = await ObtainRefreshTokenAsync(client, discovery, $"{Scopes.OpenId} {Scopes.OfflineAccess}");

        using var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            RefreshForm(refreshToken, TestConstants.ApiScope, namesResource));

        await AssertInvalidScopeAsync(response);
    }

    /// <summary>
    /// A refresh naming no resource is refused a scope only a resource its grant does not hold declares, rather than
    /// having it judged against every resource the tenant knows.
    /// </summary>
    [Fact]
    public async Task A_refresh_naming_the_scope_of_a_resource_outside_its_grant_is_refused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var refreshToken = await ObtainRefreshTokenAsync(client, discovery, GrantedScope);

        using var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            RefreshForm(refreshToken, $"{TestConstants.ApiScope} {TestConstants.OtherApiScope}", namesResource: false));

        await AssertInvalidScopeAsync(response);
    }

    /// <summary>
    /// A refresh naming a resource its grant does not hold, with the scope only that resource declares, is refused for
    /// the resource, as one naming the resource alone is, rather than for a scope no resource it speaks for declares.
    /// </summary>
    [Fact]
    public async Task A_refresh_naming_a_resource_outside_its_grant_with_its_scope_is_refused_for_the_resource()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var refreshToken = await ObtainRefreshTokenAsync(client, discovery, GrantedScope);

        using var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            [
                new(TokenRequest.Parameters.GrantType, GrantTypes.RefreshToken),
                new(TokenRequest.Parameters.RefreshToken, refreshToken),
                new(TokenRequest.Parameters.Scope, TestConstants.OtherApiScope),
                new(TokenRequest.Parameters.Resource, TestConstants.OtherApiResource),
                new(ClientRequest.Parameters.ClientId, TestConstants.ConfidentialClientId),
                new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
            ]);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"expected 400, got {(int)response.StatusCode}: {body}");
        Assert.Equal(ErrorCodes.InvalidTarget, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// A code or a refresh token refused a scope no resource of its grant declares, when the request names no resource,
    /// is redeemed by the corrected request: the refusal spends neither.
    /// </summary>
    [Theory]
    [InlineData(Code)]
    [InlineData(Refresh)]
    public async Task A_grant_refused_a_scope_stays_redeemable(string grant)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        KeyValuePair<string, string>[] redeem;
        switch (grant)
        {
            case Code:
                var (code, verifier) = await AuthorizeAsync(client, discovery, GrantedScope);
                redeem = RedeemForm(code, verifier);
                break;

            case Refresh:
                var refreshToken = await ObtainRefreshTokenAsync(client, discovery, GrantedScope);
                redeem =
                [
                    new(TokenRequest.Parameters.GrantType, GrantTypes.RefreshToken),
                    new(TokenRequest.Parameters.RefreshToken, refreshToken),
                    new(ClientRequest.Parameters.ClientId, TestConstants.ConfidentialClientId),
                    new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
                ];
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(grant), grant, null);
        }

        using var refused = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            [.. redeem, new(TokenRequest.Parameters.Scope, TestConstants.OtherApiScope)]);
        await AssertInvalidScopeAsync(refused);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, redeem);
        AssertIssuedScope([Scopes.OpenId, Scopes.OfflineAccess, TestConstants.ApiScope], tokens);
    }

    /// <summary>
    /// A code refused for naming, beside the resource it was granted for, only that resource's scope its grant does not
    /// hold is redeemed by the corrected request: the refusal comes before the code is spent.
    /// </summary>
    [Fact]
    public async Task A_code_refused_a_resource_scope_outside_its_grant_stays_redeemable()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (code, verifier) = await AuthorizeAsync(client, discovery, $"{Scopes.OpenId} {Scopes.OfflineAccess}");

        using var refused = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            [
                .. RedeemForm(code, verifier),
                new(TokenRequest.Parameters.Scope, TestConstants.ApiScope),
                new(TokenRequest.Parameters.Resource, TestConstants.ApiResource),
            ]);
        await AssertInvalidScopeAsync(refused);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, RedeemForm(code, verifier));
        AssertIssuedScope([Scopes.OpenId, Scopes.OfflineAccess], tokens);
    }

    /// <summary>The scope a request of <see cref="Matrix"/> or <see cref="IgnoredRows"/> names.</summary>
    internal static string[] Requested(string named, string tenantScope) => named switch
    {
        ResourceScope => [TestConstants.ApiScope],
        TenantScope => [tenantScope],
        BothScopes => [tenantScope, TestConstants.ApiScope],
        UnknownScope => ["not-declared"],
        _ => throw new ArgumentOutOfRangeException(nameof(named), named, null),
    };

    /// <summary>
    /// A grant the request itself authorizes speaks for no resource when the request names none, so the resource's
    /// scope is not available to it.
    /// </summary>
    private static bool IsRefused(string grant, string named, bool namesResource) => grant switch
    {
        Code or Refresh => false,
        Exchange or ClientCredentials => !namesResource && named != TenantScope,
        _ => throw new ArgumentOutOfRangeException(nameof(grant), grant, null),
    };

    private static async Task<HttpResponseMessage> RequestAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string grant,
        string scope,
        bool namesResource)
    {
        KeyValuePair<string, string>[] resource = namesResource
            ? [new(TokenRequest.Parameters.Resource, TestConstants.ApiResource)]
            : [];

        switch (grant)
        {
            case Code:
                var (code, verifier) = await AuthorizeAsync(client, discovery, GrantedScope);
                return await FormPostHelpers.PostFormAsync(
                    client,
                    discovery.TokenEndpoint,
                    [.. RedeemForm(code, verifier), new(TokenRequest.Parameters.Scope, scope), .. resource]);

            case Refresh:
                var refreshToken = await ObtainRefreshTokenAsync(client, discovery, GrantedScope);
                return await FormPostHelpers.PostFormAsync(
                    client,
                    discovery.TokenEndpoint,
                    RefreshForm(refreshToken, scope, namesResource));

            case Exchange:
                var subjectToken = await ObtainRefreshTokenAsync(client, discovery, GrantedScope);
                return await FormPostHelpers.PostFormAsync(
                    client,
                    discovery.TokenEndpoint,
                    [
                        new(TokenRequest.Parameters.GrantType, GrantTypes.TokenExchange),
                        new(TokenRequest.Parameters.SubjectToken, subjectToken),
                        new(TokenRequest.Parameters.SubjectTokenType, TokenExchangeTokenTypes.RefreshToken),
                        new(TokenRequest.Parameters.Scope, scope),
                        new(ClientRequest.Parameters.ClientId, TestConstants.ConfidentialClientId),
                        new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
                        .. resource,
                    ]);

            case ClientCredentials:
                return await FormPostHelpers.PostFormAsync(
                    client,
                    discovery.TokenEndpoint,
                    [
                        new(TokenRequest.Parameters.GrantType, GrantTypes.ClientCredentials),
                        new(TokenRequest.Parameters.Scope, scope),
                        new(ClientRequest.Parameters.ClientId, TestConstants.ClientCredentialsClientId),
                        new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
                        .. resource,
                    ]);

            default:
                throw new ArgumentOutOfRangeException(nameof(grant), grant, null);
        }
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

    private static KeyValuePair<string, string>[] RefreshForm(string refreshToken, string scope, bool namesResource) =>
    [
        new(TokenRequest.Parameters.GrantType, GrantTypes.RefreshToken),
        new(TokenRequest.Parameters.RefreshToken, refreshToken),
        new(TokenRequest.Parameters.Scope, scope),
        new(ClientRequest.Parameters.ClientId, TestConstants.ConfidentialClientId),
        new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
        .. namesResource ? [new KeyValuePair<string, string>(TokenRequest.Parameters.Resource, TestConstants.ApiResource)] : Array.Empty<KeyValuePair<string, string>>(),
    ];

    private static async Task AssertInvalidScopeAsync(HttpResponseMessage response)
    {
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"expected 400, got {(int)response.StatusCode}: {body}");
        Assert.Equal(ErrorCodes.InvalidScope, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }
}
