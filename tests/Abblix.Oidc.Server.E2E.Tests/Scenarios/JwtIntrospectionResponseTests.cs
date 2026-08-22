// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Model;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// JWT Response for OAuth Token Introspection (RFC 9701). A client registered with
/// <c>introspection_signed_response_alg</c> that introspects a token with
/// <c>Accept: application/token-introspection+jwt</c> receives the RFC 7662 response wrapped in a signed JWT under
/// the <c>token_introspection</c> claim; otherwise it receives the plain JSON document.
/// </summary>
public class JwtIntrospectionResponseTests(TestFactory factory) : TestBase(factory)
{
    private const string IntrospectionJwtMediaType = MediaTypes.TokenIntrospectionJwt;

    [Fact]
    public async Task Introspection_with_jwt_accept_returns_signed_jwt_with_token_introspection_claim()
    {
        var httpClient = CreateClient();
        var discovery = await FetchDiscoveryAsync(httpClient);
        var (clientId, clientSecret, accessToken) = await RegisterClientAndGetAccessTokenAsync(
            httpClient, discovery, introspectionSignedResponseAlg: SigningAlgorithms.RS256);

        var response = await IntrospectAsync(
            httpClient, discovery, clientId, clientSecret, accessToken, IntrospectionJwtMediaType);

        response.EnsureSuccessStatusCode();
        Assert.Equal(IntrospectionJwtMediaType, response.Content.Headers.ContentType?.MediaType);

        var jwt = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var payload = DecodeJwtPayload(jwt);

        // RFC 9701 §5: addressed to the client and issued by the AS.
        Assert.Equal(clientId, payload[IanaClaimTypes.Aud]!.GetValue<string>());
        Assert.Equal(
            discovery.Issuer.AbsoluteUri.TrimEnd('/'),
            payload[IanaClaimTypes.Iss]!.GetValue<string>().TrimEnd('/'));

        // The RFC 7662 response is carried under the token_introspection claim and reports the token as active.
        // RFC 7662 §2.2 types active as a JSON boolean, so the assertion reads it as bool.
        var introspection = payload[IanaClaimTypes.TokenIntrospection]!.AsObject();
        Assert.True(introspection[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
    }

    [Fact]
    public async Task Introspection_without_jwt_accept_returns_plain_json()
    {
        var httpClient = CreateClient();
        var discovery = await FetchDiscoveryAsync(httpClient);
        var (clientId, clientSecret, accessToken) = await RegisterClientAndGetAccessTokenAsync(
            httpClient, discovery, introspectionSignedResponseAlg: SigningAlgorithms.RS256);

        // Even though the client registered a signing algorithm, a plain JSON Accept yields the RFC 7662 document.
        var response = await IntrospectAsync(
            httpClient, discovery, clientId, clientSecret, accessToken, "application/json");

        response.EnsureSuccessStatusCode();
        Assert.NotEqual(IntrospectionJwtMediaType, response.Content.Headers.ContentType?.MediaType);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.True(body[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
    }

    [Fact]
    public async Task Discovery_advertises_introspection_signing_alg_values()
    {
        var httpClient = CreateClient();
        var discovery = await FetchDiscoveryAsync(httpClient);

        Assert.NotNull(discovery.IntrospectionSigningAlgValuesSupported);
        Assert.Contains(SigningAlgorithms.RS256, discovery.IntrospectionSigningAlgValuesSupported!);
    }

    private static async Task<(string ClientId, string ClientSecret, string AccessToken)> RegisterClientAndGetAccessTokenAsync(
        HttpClient httpClient,
        DiscoveryDocument discovery,
        string introspectionSignedResponseAlg)
    {
        var (verifier, challenge) = GeneratePkcePair();

        var dcrBody = new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            ["grant_types"] = new JsonArray { GrantTypes.AuthorizationCode },
            ["response_types"] = new JsonArray { ResponseTypes.Code },
            ["token_endpoint_auth_method"] = "client_secret_post",
            [ClientRegistrationRequest.Parameters.IntrospectionSignedResponseAlg] = introspectionSignedResponseAlg,
        };
        var registered = await RegisterClientAsync(httpClient, discovery, dcrBody);
        var clientId = registered[AuthorizationRequest.Parameters.ClientId]!.GetValue<string>();
        var clientSecret = registered[ClientRequest.Parameters.ClientSecret]!.GetValue<string>();

        var code = await AuthorizeAndExtractCodeAsync(httpClient, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        });

        var tokenResponse = await ExchangeCodeForTokensAsync(httpClient, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
        });

        var accessToken = tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        return (clientId, clientSecret, accessToken);
    }

    private static async Task<HttpResponseMessage> IntrospectAsync(
        HttpClient httpClient,
        DiscoveryDocument discovery,
        string clientId,
        string clientSecret,
        string token,
        string acceptMediaType)
    {
        Assert.NotNull(discovery.IntrospectionEndpoint);

        var request = new HttpRequestMessage(HttpMethod.Post, discovery.IntrospectionEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [IntrospectionRequest.Parameters.Token] = token,
                [AuthorizationRequest.Parameters.ClientId] = clientId,
                [ClientRequest.Parameters.ClientSecret] = clientSecret,
            }),
        };
        request.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(acceptMediaType));

        return await httpClient.SendAsync(request);
    }
}
