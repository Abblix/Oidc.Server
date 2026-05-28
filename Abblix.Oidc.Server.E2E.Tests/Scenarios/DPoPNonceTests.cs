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
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Xunit;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9449 §8 (AS) and §9 (RS) DPoP-Nonce challenge-response tests. The default
/// <see cref="TestFactory"/> ships with nonce enforcement OFF; these tests run against
/// <see cref="NonceEnabledTestFactory"/> (RequireAtTokenEndpoint and
/// RequireAtUserInfoEndpoint both = true) under a dedicated xunit collection so the
/// singleton factory state never leaks to the rest of the DPoP suite.
/// </summary>
[Collection(DPoPNonceTestCollection.Name)]
public class DPoPNonceTests(NonceEnabledTestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task Token_endpoint_with_proof_lacking_nonce_returns_use_dpop_nonce_challenge_with_header()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var (_, _, nonce, challengeBody, challengeResponse) =
            await NavigateTokenNonceChallengeAsync(client, discovery, proofKey);

        Assert.Equal(HttpStatusCode.BadRequest, challengeResponse.StatusCode);
        Assert.Equal(ErrorCodes.UseDPoPNonce, challengeBody["error"]!.GetValue<string>());
        Assert.False(string.IsNullOrEmpty(nonce));
    }

    [Fact]
    public async Task Token_endpoint_retry_with_nonce_from_challenge_succeeds()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokenBody = await ObtainDPoPBoundTokenViaNonceFlowAsync(client, discovery, proofKey);

        Assert.Equal(TokenTypes.DPoP,
            tokenBody[BackChannelTokenPushRequest.Parameters.TokenType]!.GetValue<string>());
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
        var accessToken = (await ObtainDPoPBoundTokenViaNonceFlowAsync(client, discovery, proofKey))
            [UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        // First UserInfo call: no nonce on the proof — RS issues a fresh nonce challenge
        // (RFC 9449 §9 + §7.1 SHOULD WWW-Authenticate: DPoP).
        var proofWithoutNonce = proofKey.BuildProof(
            HttpMethods.Get, discovery.UserInfoEndpoint!, accessToken: accessToken);
        var response = await SendUserInfoAsync(client, discovery, accessToken, proofWithoutNonce);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate,
            h => h.Scheme == TokenTypes.DPoP && (h.Parameter ?? string.Empty).Contains(ErrorCodes.UseDPoPNonce));
        Assert.True(response.Headers.TryGetValues(HttpRequestHeaders.DPoPNonce, out var nonceValues),
            "UserInfo challenge response missing DPoP-Nonce header");
        Assert.False(string.IsNullOrEmpty(nonceValues.First()));
    }

    [Fact]
    public async Task UserInfo_retry_with_nonce_from_challenge_succeeds()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = (await ObtainDPoPBoundTokenViaNonceFlowAsync(client, discovery, proofKey))
            [UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        // Step 1: no nonce → challenge carries fresh nonce.
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

    // ───────────────────────────────────────────────────────────────────────
    // Helpers — DPoP-aware flow primitives. Non-DPoP boilerplate (discovery,
    // /authorize redirect parsing) is inherited from TestBase.
    // ───────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Bootstraps PAR + /authorize, then makes the first /token call with a proof that
    /// carries no nonce — the AS issues a 400 + <c>use_dpop_nonce</c> + a fresh
    /// <c>DPoP-Nonce</c> response header (RFC 9449 §8). Returns the PKCE verifier, the
    /// auth code (still spendable per §8 retry semantics), the fresh nonce, the parsed
    /// error body, and the raw response so callers can pin extra assertions.
    /// </summary>
    private static async Task<(string Verifier, string Code, string Nonce, JsonObject Body, HttpResponseMessage Response)>
        NavigateTokenNonceChallengeAsync(
            HttpClient client,
            DiscoveryDocument discovery,
            DPoPProofGenerator proofKey)
    {
        var (verifier, challenge) = GeneratePkcePair();
        var parResponse = await PushAuthorizationRequestAsync(client, discovery, BuildParForm(challenge));
        var requestUri = parResponse[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.DPoPRequiredClientId,
            [AuthorizationRequest.Parameters.RequestUri] = requestUri,
        });

        var proofWithoutNonce = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var response = await SendTokenAsync(client, discovery, code, verifier, proofWithoutNonce);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var body = JsonNode.Parse(raw)!.AsObject();
        var nonce = response.Headers.TryGetValues(HttpRequestHeaders.DPoPNonce, out var values)
            ? values.First()
            : string.Empty;
        return (verifier, code, nonce, body, response);
    }

    /// <summary>
    /// Walks the full token-endpoint nonce dance — first request gets a challenge, second
    /// embeds the issued nonce and succeeds — and returns the parsed success-body. Used
    /// directly by the retry-success test and as bootstrap for the §9 UserInfo nonce tests.
    /// </summary>
    private static async Task<JsonObject> ObtainDPoPBoundTokenViaNonceFlowAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        DPoPProofGenerator proofKey)
    {
        var (verifier, code, nonce, _, _) = await NavigateTokenNonceChallengeAsync(client, discovery, proofKey);

        var proofWithNonce = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint, nonce: nonce);
        var response = await SendTokenAsync(client, discovery, code, verifier, proofWithNonce);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode,
            $"/token retry failed: {(int)response.StatusCode} {raw}");
        return JsonNode.Parse(raw)!.AsObject();
    }

    private static Dictionary<string, string> BuildParForm(string challenge) => new()
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
        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint);
        request.Content = new FormUrlEncodedContent(form);
        request.WithDPoPHeader(proofJwt);
        return await client.SendAsync(request);
    }

    /// <summary>
    /// Sends a GET to /userinfo presenting <paramref name="accessToken"/> under the DPoP
    /// scheme together with the supplied proof. Returns the raw response so callers can
    /// inspect status, WWW-Authenticate challenges, and DPoP-Nonce headers.
    /// </summary>
    private static async Task<HttpResponseMessage> SendUserInfoAsync(
        HttpClient client, DiscoveryDocument discovery, string accessToken, string proofJwt)
    {
        Assert.NotNull(discovery.UserInfoEndpoint);
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.DPoP, accessToken);
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
