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
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 4.1.1: redirect_uri is "OPTIONAL if only one redirect URI is registered
/// for this client", and section 10.2 removes it from the token request of a code issued with PKCE, while a code issued
/// without PKCE keeps RFC 6749 section 4.1.3: required at the token endpoint where the authorization request included
/// it. An OpenID Connect request keeps redirect_uri required (OpenID Connect Core 1.0 section 3.1.2.1).
/// </summary>
public class OmittedRedirectUriTests(TestFactory factory) : TestBase(factory)
{
    private const string WithoutPkceClientId = "e2e-oauth-without-pkce";
    private const string TwoRedirectUrisClientId = "e2e-oauth-two-redirect-uris";
    private const string OtherRedirectUri = "https://client.example.com/other";

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ARequestNamingNoRedirectUri_IsServedAtTheSoleRegisteredOne_AndRedeemedWithoutIt(bool pkce)
    {
        await using var host = Host();
        using var client = CreateClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        var clientId = pkce ? TestConstants.UnrestrictedClientId : WithoutPkceClientId;

        var (location, verifier) = await AuthorizeAsync(client, discovery, clientId, redirectUri: null, pkce);

        Assert.StartsWith(TestConstants.RedirectUri + "?", location.OriginalString, StringComparison.Ordinal);
        var code = System.Web.HttpUtility.ParseQueryString(location.Query)[ResponseParameters.Code];
        Assert.NotNull(code);

        using var response = await RedeemAsync(client, discovery, clientId, code, verifier, redirectUri: null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// OAuth 2.1 section 10.2: a client with several redirect URIs names one at the authorization endpoint and, with
    /// PKCE, none at the token endpoint.
    /// </summary>
    [Fact]
    public async Task ACodeIssuedWithPkce_ToARequestNamingTheRedirectUri_IsRedeemedWithoutIt()
    {
        await using var host = Host();
        using var client = CreateClient(host);
        var discovery = await FetchDiscoveryAsync(client);

        var (location, verifier) = await AuthorizeAsync(
            client, discovery, TwoRedirectUrisClientId, OtherRedirectUri, pkce: true);
        var code = System.Web.HttpUtility.ParseQueryString(location.Query)[ResponseParameters.Code];
        Assert.NotNull(code);

        using var response = await RedeemAsync(client, discovery, TwoRedirectUrisClientId, code, verifier, null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// RFC 6749 section 4.1.3: a code issued without PKCE to a request naming the redirect URI asks for it again.
    /// </summary>
    [Fact]
    public async Task ACodeIssuedWithoutPkce_ToARequestNamingTheRedirectUri_IsNotRedeemedWithoutIt()
    {
        await using var host = Host();
        using var client = CreateClient(host);
        var discovery = await FetchDiscoveryAsync(client);

        var (location, _) = await AuthorizeAsync(
            client, discovery, WithoutPkceClientId, TestConstants.RedirectUri, pkce: false);
        var code = System.Web.HttpUtility.ParseQueryString(location.Query)[ResponseParameters.Code];
        Assert.NotNull(code);

        using var response = await RedeemAsync(client, discovery, WithoutPkceClientId, code, null, null);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidRequest, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// An OpenID Connect request, and a request of a client with several redirect URIs, naming none is refused
    /// without a redirect (OAuth 2.1 section 4.1.2.1: the server "MUST NOT redirect the user agent to the invalid
    /// redirect URI").
    /// </summary>
    [Theory]
    [InlineData(TestConstants.UnrestrictedClientId, Scopes.OpenId)]
    [InlineData(TwoRedirectUrisClientId, Scopes.Profile)]
    public async Task ARequestNamingNoRedirectUri_ThatHasToNameOne_IsRefusedWithoutARedirect(string clientId, string scope)
    {
        await using var host = Host();
        using var client = CreateClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        var (_, challenge) = GeneratePkcePair();

        using var response = await client.GetAsync(QueryHelpers.BuildUri(discovery.AuthorizationEndpoint,
            new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = clientId,
                [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
                [AuthorizationRequest.Parameters.Scope] = scope,
                [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
                [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
                [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    private static async Task<(Uri Location, string? Verifier)> AuthorizeAsync(
        HttpClient client, DiscoveryDocument discovery, string clientId, string? redirectUri, bool pkce)
    {
        var parameters = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.Scope] = Scopes.Profile,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
        };
        if (redirectUri is not null)
            parameters[AuthorizationRequest.Parameters.RedirectUri] = redirectUri;

        string? verifier = null;
        if (pkce)
        {
            (verifier, var challenge) = GeneratePkcePair();
            parameters[AuthorizationRequest.Parameters.CodeChallenge] = challenge;
            parameters[AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256;
        }

        using var response = await client.GetAsync(QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters));
        Assert.True(
            response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"/authorize returned {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
        return (response.Headers.Location!, verifier);
    }

    private static Task<HttpResponseMessage> RedeemAsync(
        HttpClient client, DiscoveryDocument discovery, string clientId, string code, string? verifier, string? redirectUri)
    {
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [ClientRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        };
        if (verifier is not null)
            form[TokenRequest.Parameters.CodeVerifier] = verifier;
        if (redirectUri is not null)
            form[TokenRequest.Parameters.RedirectUri] = redirectUri;

        return FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form);
    }

    private static HttpClient CreateClient(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    /// <summary>
    /// The shared host with a client not required to use PKCE and a client registering two redirect URIs, both with
    /// one secret and the code grant.
    /// </summary>
    private WebApplicationFactory<Program> Host()
        => Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.PostConfigure<TestTenantSettings>(tenant =>
            {
                tenant.Clients =
                [
                    ..tenant.Clients,
                    CodeClient(WithoutPkceClientId, pkceRequired: false, new Uri(TestConstants.RedirectUri)),
                    CodeClient(
                        TwoRedirectUrisClientId,
                        pkceRequired: true,
                        new Uri(TestConstants.RedirectUri),
                        new Uri(OtherRedirectUri)),
                ];
            })));

    private static ClientInfo CodeClient(string clientId, bool pkceRequired, params Uri[] redirectUris) => new(clientId)
    {
        ClientSecrets =
        [
            new ClientSecret
            {
                Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(TestConstants.ConfidentialClientSecret)),
            },
        ],
        TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
        AllowedGrantTypes = [GrantTypes.AuthorizationCode],
        PkceRequired = pkceRequired,
        RedirectUris = redirectUris,
    };
}
