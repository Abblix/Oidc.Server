// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9449 §8 DPoP-Nonce challenge-response tests. The default <see cref="TestFactory"/>
/// ships with nonce enforcement OFF; these tests run against <see cref="NonceEnabledTestFactory"/>
/// (RequireAtTokenEndpoint = true) under a dedicated xunit collection so the singleton
/// factory state never leaks to the rest of the DPoP suite.
/// </summary>
[Collection(DPoPNonceTestCollection.Name)]
public class DPoPNonceTests
{
    private readonly NonceEnabledTestFactory _factory;

    public DPoPNonceTests(NonceEnabledTestFactory factory) => _factory = factory;

    private HttpClient CreateClient() => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        BaseAddress = new Uri("https://localhost"),
    });

    [Fact]
    public async Task Token_endpoint_with_proof_lacking_nonce_returns_use_dpop_nonce_challenge_with_header()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var (parResponse, verifier, _) = await PushParAsync(client, discovery);
        var requestUri = (await ReadBodyAsync(parResponse))[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();
        var code = await AuthorizeAsync(client, discovery, requestUri);

        // Real verifier matters — PKCE validation runs before the DPoP nonce check,
        // so a fake verifier short-circuits on invalid_grant and we never observe the
        // RFC 9449 §8 challenge we're actually testing for.
        var proofWithoutNonce = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var tokenResponse = await SendTokenAsync(client, discovery, code, verifier, proofWithoutNonce);

        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        var body = await ReadBodyAsync(tokenResponse);
        Assert.Equal(ErrorCodes.UseDPoPNonce, body["error"]!.GetValue<string>());

        // RFC 9449 §8: the challenge response carries the fresh nonce in a header so
        // the client knows what value to embed in the next proof.
        Assert.True(tokenResponse.Headers.TryGetValues(HttpRequestHeaders.DPoPNonce, out var nonceValues),
            "Response missing DPoP-Nonce header");
        Assert.Single(nonceValues!);
        Assert.False(string.IsNullOrEmpty(nonceValues!.First()));
    }

    // ───────────────────────────────────────────────────────────────────────
    // Resource-server-side nonce challenge (RFC 9449 §9)
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task UserInfo_with_dpop_proof_lacking_nonce_returns_use_dpop_nonce_challenge()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        // Navigate the token-endpoint nonce challenge first so we have a DPoP-bound
        // access token to present at /userinfo.
        var accessToken = await ObtainDPoPBoundTokenViaNonceFlowAsync(client, discovery, proofKey);

        // First UserInfo call: no nonce on the proof — RS issues a fresh nonce challenge
        // (RFC 9449 §9 + §7.1 SHOULD WWW-Authenticate: DPoP).
        var firstProof = proofKey.BuildProof(
            HttpMethods.Get, discovery.UserInfoEndpoint!, accessToken: accessToken);
        var response = await SendUserInfoAsync(client, discovery, accessToken, firstProof);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate,
            h => h.Scheme == TokenTypes.DPoP && (h.Parameter ?? string.Empty).Contains(ErrorCodes.UseDPoPNonce));
        Assert.True(response.Headers.TryGetValues(HttpRequestHeaders.DPoPNonce, out var nonceValues),
            "UserInfo challenge response missing DPoP-Nonce header");
        Assert.False(string.IsNullOrEmpty(nonceValues!.First()));
    }

    [Fact]
    public async Task UserInfo_retry_with_nonce_from_challenge_succeeds()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = await ObtainDPoPBoundTokenViaNonceFlowAsync(client, discovery, proofKey);

        // Step 1: no nonce -> challenge carries fresh nonce.
        var firstProof = proofKey.BuildProof(
            HttpMethods.Get, discovery.UserInfoEndpoint!, accessToken: accessToken);
        var challenge = await SendUserInfoAsync(client, discovery, accessToken, firstProof);
        Assert.Equal(HttpStatusCode.Unauthorized, challenge.StatusCode);
        var nonce = challenge.Headers.GetValues(HttpRequestHeaders.DPoPNonce).First();

        // Step 2: retry with the supplied nonce embedded in the proof.
        var secondProof = proofKey.BuildProof(
            HttpMethods.Get, discovery.UserInfoEndpoint!, accessToken: accessToken, nonce: nonce);
        var success = await SendUserInfoAsync(client, discovery, accessToken, secondProof);

        var raw = await success.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(success.IsSuccessStatusCode,
            $"/userinfo retry failed: {(int)success.StatusCode} {raw}");
    }

    [Fact]
    public async Task Token_endpoint_retry_with_nonce_from_challenge_succeeds()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var (parResponse, verifier, _) = await PushParAsync(client, discovery);
        var requestUri = (await ReadBodyAsync(parResponse))[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();
        var code = await AuthorizeAsync(client, discovery, requestUri);

        // Step 1: proof without nonce -> challenge carries fresh nonce on DPoP-Nonce header.
        var firstProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var firstResponse = await SendTokenAsync(client, discovery, code, verifier, firstProof);
        Assert.Equal(HttpStatusCode.BadRequest, firstResponse.StatusCode);
        var nonce = firstResponse.Headers.GetValues(HttpRequestHeaders.DPoPNonce).First();

        // Step 2: retry with the nonce embedded; same auth code (RFC 9449 §8 retry semantics).
        var secondProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint, nonce: nonce);
        var secondResponse = await SendTokenAsync(client, discovery, code, verifier, secondProof);

        var raw = await secondResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(secondResponse.IsSuccessStatusCode, $"/token retry failed: {(int)secondResponse.StatusCode} {raw}");
        var tokenBody = JsonNode.Parse(raw)!.AsObject();
        Assert.Equal(TokenTypes.DPoP, tokenBody[BackChannelTokenPushRequest.Parameters.TokenType]!.GetValue<string>());
    }

    // ───────────────────────────────────────────────────────────────────────
    // Per-test helpers — slim copies of TestBase pieces that are static there
    // but get a different fixture in this collection. Hidden in private methods
    // so the [Fact] bodies stay flow-step readable.
    // ───────────────────────────────────────────────────────────────────────

    private static async Task<DiscoveryDocument> FetchDiscoveryAsync(HttpClient client)
    {
        var response = await client.GetAsync("/.well-known/openid-configuration");
        response.EnsureSuccessStatusCode();
        var doc = await System.Net.Http.Json.HttpContentJsonExtensions
            .ReadFromJsonAsync<DiscoveryDocument>(response.Content);
        return doc!;
    }

    private static async Task<(HttpResponseMessage, string Verifier, string Challenge)> PushParAsync(
        HttpClient client, DiscoveryDocument discovery)
    {
        var (verifier, challenge) = TestBase.GeneratePkcePair();
        var form = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.DPoPRequiredClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.PushedAuthorizationRequestEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        var response = await client.SendAsync(request);
        Assert.True(response.IsSuccessStatusCode, $"PAR failed: {(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        return (response, verifier, challenge);
    }

    private static async Task<string> AuthorizeAsync(HttpClient client, DiscoveryDocument discovery, string requestUri)
    {
        var uri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.DPoPRequiredClientId,
            [AuthorizationRequest.Parameters.RequestUri] = requestUri,
        });
        var response = await client.GetAsync(uri);
        Assert.True(response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found,
            $"/authorize unexpected: {(int)response.StatusCode}");
        var location = response.Headers.Location!;
        return System.Web.HttpUtility.ParseQueryString(location.Query)[TokenRequest.Parameters.Code]!;
    }

    private static async Task<HttpResponseMessage> SendTokenAsync(
        HttpClient client, DiscoveryDocument discovery, string code, string verifier, string proofJwt)
    {
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.DPoPRequiredClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        request.WithDPoPHeader(proofJwt);
        return await client.SendAsync(request);
    }

    private static async Task<JsonObject> ReadBodyAsync(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync();
        return JsonNode.Parse(raw)!.AsObject();
    }

    /// <summary>
    /// Drives the full token-endpoint nonce-challenge dance with <paramref name="proofKey"/>
    /// and returns the resulting DPoP-bound access token. Used by /userinfo nonce tests
    /// because <see cref="NonceEnabledTestFactory"/> also enables the token-endpoint
    /// nonce, so a real access token cannot be obtained without first satisfying that
    /// challenge.
    /// </summary>
    private static async Task<string> ObtainDPoPBoundTokenViaNonceFlowAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        DPoPProofGenerator proofKey)
    {
        var (parResponse, verifier, _) = await PushParAsync(client, discovery);
        var requestUri = (await ReadBodyAsync(parResponse))[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();
        var code = await AuthorizeAsync(client, discovery, requestUri);

        var firstProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var firstResponse = await SendTokenAsync(client, discovery, code, verifier, firstProof);
        Assert.Equal(HttpStatusCode.BadRequest, firstResponse.StatusCode);
        var nonce = firstResponse.Headers.GetValues(HttpRequestHeaders.DPoPNonce).First();

        var secondProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint, nonce: nonce);
        var secondResponse = await SendTokenAsync(client, discovery, code, verifier, secondProof);
        var raw = await secondResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(secondResponse.IsSuccessStatusCode,
            $"Token request after nonce retry failed: {(int)secondResponse.StatusCode} {raw}");
        var body = JsonNode.Parse(raw)!.AsObject();
        return body[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
    }

    /// <summary>
    /// Sends a GET to /userinfo presenting <paramref name="accessToken"/> under the DPoP
    /// scheme together with the supplied proof. Returns the raw response so callers can
    /// inspect status, WWW-Authenticate challenges, and DPoP-Nonce headers.
    /// </summary>
    private static async Task<HttpResponseMessage> SendUserInfoAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string accessToken,
        string proofJwt)
    {
        Assert.NotNull(discovery.UserInfoEndpoint);
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(TokenTypes.DPoP, accessToken);
        request.WithDPoPHeader(proofJwt);
        return await client.SendAsync(request);
    }
}

/// <summary>
/// Dedicated xunit collection for nonce-enabled scenarios — separate from
/// <c>TestCollection</c> so the singleton <see cref="NonceEnabledTestFactory"/>
/// fixture's per-host options never leak into the default-flow DPoP tests.
/// </summary>
[CollectionDefinition(Name)]
public sealed class DPoPNonceTestCollection : ICollectionFixture<NonceEnabledTestFactory>
{
    public const string Name = "DPoPNonce";
}
