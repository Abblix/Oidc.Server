// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// RFC 9449 section 8 (AS) and section 9 (RS) DPoP-Nonce challenge-response tests. The default
/// <see cref="TestFactory"/> ships with nonce enforcement OFF; these tests run against
/// <see cref="NonceEnabledTestFactory"/> (RequireAtTokenEndpoint and
/// RequireAtUserInfoEndpoint both = true) under a dedicated xunit collection so the
/// singleton factory state never leaks to the rest of the DPoP suite.
/// </summary>
public class DPoPNonceTests(NonceEnabledTestFactory factory) : TestBase(factory)
{
    private const string Realm = "realm";
    private const string Algorithms = "algs";

    [Fact]
    public async Task Token_endpoint_with_proof_lacking_nonce_returns_use_dpop_nonce_challenge_with_header()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var (_, _, nonce, challengeBody, challengeResponse) =
            await NavigateTokenNonceChallengeAsync(client, discovery, proofKey);

        Assert.Equal(HttpStatusCode.BadRequest, challengeResponse.StatusCode);
        Assert.Equal(ErrorCodes.UseDPoPNonce, challengeBody[ErrorResponse.Parameters.Error]!.GetValue<string>());
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
            tokenBody[TokenResponse.Parameters.TokenType]!.GetValue<string>());
    }

    [Fact]
    public async Task UserInfo_with_dpop_proof_lacking_nonce_returns_use_dpop_nonce_challenge()
    {
        // No nonce on the proof - RS issues a fresh nonce challenge
        // (RFC 9449 section 9 + section 7.1 SHOULD WWW-Authenticate: DPoP).
        var response = await SendUserInfoWithoutNonceAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var (dpop, _) = DualChallengeReader.Challenges(response);
        Assert.Equal(ErrorCodes.UseDPoPNonce, dpop.Parameters[ErrorResponse.Parameters.Error]);
        Assert.True(response.Headers.TryGetValues(HttpRequestHeaders.DPoPNonce, out var nonceValues),
            "UserInfo challenge response missing DPoP-Nonce header");
        Assert.False(string.IsNullOrEmpty(nonceValues.First()));
    }

    /// <summary>
    /// The nonce refusal answers a request that presented its token over DPoP, so it is the DPoP challenge that says
    /// so, and the Bearer one beside it stays bare. RFC 9449 section 9: "The error signaling is performed as described
    /// in Section 7.1. Resource servers use an HTTP 401 (Unauthorized) error code with an accompanying
    /// WWW-Authenticate: DPoP value and DPoP-Nonce value to accomplish this." Section 7.2: "If the mechanism used to
    /// attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information."
    /// </summary>
    [Fact]
    public async Task UserInfo_nonce_refusal_carries_its_error_on_the_dpop_challenge_and_none_on_the_bearer_one()
    {
        var response = await SendUserInfoWithoutNonceAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var (dpop, bearer) = DualChallengeReader.Challenges(response);
        ChallengeAssert.Carries(
            dpop,
            TokenTypes.DPoP,
            (Realm, null),
            (ErrorResponse.Parameters.Error, ErrorCodes.UseDPoPNonce),
            (ErrorResponse.Parameters.ErrorDescription, null),
            (Algorithms, null));
        ChallengeAssert.Carries(bearer, TokenTypes.Bearer, (Realm, null));
    }

    [Fact]
    public async Task UserInfo_retry_with_nonce_from_challenge_succeeds()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = (await ObtainDPoPBoundTokenViaNonceFlowAsync(client, discovery, proofKey))
            [TokenResponse.Parameters.AccessToken]!.GetValue<string>();

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

    /// <summary>
    /// Bootstraps PAR + /authorize, then makes the first /token call with a proof that
    /// carries no nonce - the AS issues a 400 + <c>use_dpop_nonce</c> + a fresh
    /// <c>DPoP-Nonce</c> response header (RFC 9449 section 8). Returns the PKCE verifier, the
    /// auth code (still spendable per section 8 retry semantics), the fresh nonce, the parsed
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
        var requestUri = parResponse[PushedAuthorizationResponse.Parameters.RequestUri]!.GetValue<string>();
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
    /// Walks the full token-endpoint nonce dance - first request gets a challenge, second
    /// embeds the issued nonce and succeeds - and returns the parsed success-body. Used
    /// directly by the retry-success test and as bootstrap for the section 9 UserInfo nonce tests.
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
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [ClientRequest.Parameters.ClientId] = TestConstants.DPoPRequiredClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        };
        return await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form, proofJwt);
    }

    /// <summary>
    /// Obtains a DPoP-bound access token through the token endpoint's nonce flow, then presents it at /userinfo with a
    /// proof carrying no nonce, which the resource server answers with its own nonce challenge (RFC 9449 section 9).
    /// </summary>
    private async Task<HttpResponseMessage> SendUserInfoWithoutNonceAsync()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = (await ObtainDPoPBoundTokenViaNonceFlowAsync(client, discovery, proofKey))
            [TokenResponse.Parameters.AccessToken]!.GetValue<string>();

        var proofWithoutNonce = proofKey.BuildProof(
            HttpMethods.Get, discovery.UserInfoEndpoint!, accessToken: accessToken);
        return await SendUserInfoAsync(client, discovery, accessToken, proofWithoutNonce);
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
