// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9449 Demonstrating Proof-of-Possession (DPoP) end-to-end against the test OIDC
/// provider. Each test mints a proof with a per-instance ECDSA P-256 keypair, threads
/// it through the real HTTP flow (PAR -> /authorize -> /token), and asserts on the
/// wire-level outcome: the issued access token's <c>cnf.jkt</c> claim, the wire
/// <c>token_type</c>, or the error code returned by the AS.
/// </summary>
/// <remarks>
/// Two seeded clients drive the matrix:
/// <see cref="TestConstants.DPoPRequiredClientId"/> -- <c>RequireDPoP = true</c>
/// (mandatory binding; missing proof -> reject) and
/// <see cref="TestConstants.DPoPOpportunisticClientId"/> -- <c>RequireDPoP = false</c>
/// (proof optional; when present the AS still binds, RFC 9449 §5.2 opportunistic posture).
/// Lower-level helpers from <see cref="TestBase"/> are used directly rather than
/// <c>PerformParFlowAsync</c> because DPoP scenarios need different proofs on different
/// endpoints (one per request) and a few exercise PAR-only or token-only deviations
/// that the wrapper hides.
/// </remarks>
public class DPoPTests(TestFactory factory) : TestBase(factory)
{
    // ───────────────────────────────────────────────────────────────────────
    // Opportunistic binding (RFC 9449 §5.2)
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Opportunistic_client_with_proof_at_token_endpoint_gets_dpop_bound_access_token()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: proofKey.BuildProof("POST", new Uri(discovery.TokenEndpoint)));

        AssertDPoPBound(tokenResponse, expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Opportunistic_client_without_proof_gets_bearer_access_token()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: null);

        AssertBearer(tokenResponse);
    }

    // ───────────────────────────────────────────────────────────────────────
    // Mandatory binding (RFC 9449 §5.2 + ClientInfo.RequireDPoP)
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Required_client_with_valid_proof_gets_dpop_bound_access_token()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPRequiredClientId,
            parProof: null,
            tokenProof: proofKey.BuildProof("POST", new Uri(discovery.TokenEndpoint)));

        AssertDPoPBound(tokenResponse, expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Required_client_without_proof_is_rejected_with_invalid_dpop_proof()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokenError = await DriveParAuthorizeTokenExpectingErrorAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPRequiredClientId,
            parProof: null,
            tokenProof: null);

        Assert.Equal(ErrorCodes.InvalidDPoPProof, tokenError);
    }

    // ───────────────────────────────────────────────────────────────────────
    // PAR carry-over (RFC 9449 §10): dpop_jkt commits at PAR, must match at /token
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Proof_at_par_commits_dpop_jkt_and_matching_proof_at_token_succeeds()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var parProof = proofKey.BuildProof("POST", new Uri(discovery.PushedAuthorizationRequestEndpoint!));
        var tokenProof = proofKey.BuildProof("POST", new Uri(discovery.TokenEndpoint));

        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: parProof,
            tokenProof: tokenProof);

        AssertDPoPBound(tokenResponse, expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Proof_at_par_followed_by_different_key_at_token_is_rejected()
    {
        // RFC 9449 §10: dpop_jkt committed at PAR pins which key the token endpoint
        // must see; a different key proves the auth code was hijacked by another client.
        using var parKey = new DPoPProofGenerator();
        using var tokenKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var parProof = parKey.BuildProof("POST", new Uri(discovery.PushedAuthorizationRequestEndpoint!));
        var tokenProof = tokenKey.BuildProof("POST", new Uri(discovery.TokenEndpoint));

        var tokenError = await DriveParAuthorizeTokenExpectingErrorAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: parProof,
            tokenProof: tokenProof);

        Assert.Equal(ErrorCodes.InvalidDPoPProof, tokenError);
    }

    [Fact]
    public async Task Carry_over_committed_at_par_but_no_proof_at_token_is_rejected()
    {
        // The canonical RFC 9449 §10 attack window: PAR pinned a key, but the redeemer
        // shows up at /token without a proof. Even an opportunistic-binding client MUST
        // reject -- the PAR-time commitment is unconditional.
        using var parKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var parProof = parKey.BuildProof("POST", new Uri(discovery.PushedAuthorizationRequestEndpoint!));

        var tokenError = await DriveParAuthorizeTokenExpectingErrorAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: parProof,
            tokenProof: null);

        Assert.Equal(ErrorCodes.InvalidDPoPProof, tokenError);
    }

    // ───────────────────────────────────────────────────────────────────────
    // Replay protection (RFC 9449 §11.1)
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Same_proof_jwt_presented_twice_is_rejected_on_the_second_attempt()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        // Mint ONE proof and reuse it across two independent flows. First flow succeeds
        // and the AS caches the proof's jti; second flow with the same proof string trips
        // the replay cache regardless of which other request parameters change.
        var sharedProof = proofKey.BuildProof("POST", new Uri(discovery.TokenEndpoint));

        var firstResponse = await DriveParAuthorizeTokenAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: sharedProof);
        AssertDPoPBound(firstResponse, expectedThumbprint: proofKey.Thumbprint);

        var secondError = await DriveParAuthorizeTokenExpectingErrorAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: sharedProof);
        Assert.Equal(ErrorCodes.InvalidDPoPProof, secondError);
    }

    // ───────────────────────────────────────────────────────────────────────
    // UserInfo endpoint (RFC 9449 §7) — resource-server-side proof validation
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task UserInfo_with_dpop_bound_token_and_matching_proof_succeeds()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = await ObtainDPoPBoundAccessTokenAsync(client, discovery, proofKey);

        // RFC 9449 §7.1: proof must carry ath = base64url(sha256(access_token)).
        var userInfoProof = proofKey.BuildProof(
            "GET", new Uri(discovery.UserInfoEndpoint!), accessToken: accessToken);

        var response = await SendUserInfoAsync(
            client, discovery, accessToken, userInfoProof, scheme: TokenTypes.DPoP);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"/userinfo failed: {(int)response.StatusCode} {body}");
    }

    [Fact]
    public async Task UserInfo_dpop_bound_token_presented_as_bearer_is_rejected()
    {
        // RFC 9449 §7.2: "such a protected resource MUST reject a DPoP-bound access
        // token received as a bearer token". The check exists to close the downgrade-
        // to-Bearer attack surface. RFC 9449 §7.1 also asks the response to carry a
        // WWW-Authenticate: DPoP challenge so the client knows which scheme to switch to.
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = await ObtainDPoPBoundAccessTokenAsync(client, discovery, proofKey);

        var response = await SendUserInfoAsync(
            client, discovery, accessToken, proofJwt: null, scheme: TokenTypes.Bearer);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == TokenTypes.DPoP);
    }

    [Fact]
    public async Task UserInfo_unbound_token_presented_as_dpop_is_rejected()
    {
        // Abblix-side defensive posture: RFC 9449 §7.1's check list "the public key of
        // the DPoP proof matches the public key to which the access token is bound"
        // has no defined behaviour when the token carries no cnf.jkt at all (nothing
        // to match against). Abblix chooses to reject so a Bearer-issued token cannot
        // silently sneak through the DPoP scheme and bypass logging/policy gates that
        // key off presentation mode. Not a spec MUST -- a deliberate posture.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null, tokenProof: null);
        var unboundAccessToken = tokenResponse[WireParameters.AccessToken]!.GetValue<string>();

        // Attach a syntactically valid proof to make sure the rejection is about the
        // token's binding state, not about a missing proof header.
        using var proofKey = new DPoPProofGenerator();
        var proof = proofKey.BuildProof(
            "GET", new Uri(discovery.UserInfoEndpoint!), accessToken: unboundAccessToken);

        var response = await SendUserInfoAsync(
            client, discovery, unboundAccessToken, proof, scheme: TokenTypes.DPoP);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == TokenTypes.DPoP);
    }

    [Fact]
    public async Task UserInfo_dpop_bound_token_with_proof_signed_by_different_key_is_rejected()
    {
        using var bindingKey = new DPoPProofGenerator();
        using var attackerKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = await ObtainDPoPBoundAccessTokenAsync(client, discovery, bindingKey);

        // Proof signed with a different key — the attacker stole the token but lacks the
        // private key the token was bound to. The AS computes the proof's jkt and finds
        // it doesn't match the token's cnf.jkt. RFC 9449 §7.1: the resource server SHOULD
        // accompany the 401 with a WWW-Authenticate: DPoP challenge so the client knows
        // which scheme to use on retry.
        var attackerProof = attackerKey.BuildProof(
            "GET", new Uri(discovery.UserInfoEndpoint!), accessToken: accessToken);

        var response = await SendUserInfoAsync(
            client, discovery, accessToken, attackerProof, scheme: TokenTypes.DPoP);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == TokenTypes.DPoP);
    }

    // ───────────────────────────────────────────────────────────────────────
    // Discovery metadata (RFC 9449 §5.1)
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Discovery_exposes_dpop_signing_alg_values_supported()
    {
        var discovery = await FetchDiscoveryAsync(CreateClient());

        Assert.NotNull(discovery.DPoPSigningAlgValuesSupported);
        // RFC 9449 §4.2 alg whitelist (no HMAC, no none); the AS advertises an asymmetric
        // subset. We pin a few canonical values; full enumeration is a unit-test concern.
        Assert.Contains(SigningAlgorithms.ES256, discovery.DPoPSigningAlgValuesSupported!);
        Assert.Contains(SigningAlgorithms.RS256, discovery.DPoPSigningAlgValuesSupported!);
        Assert.Contains(SigningAlgorithms.PS256, discovery.DPoPSigningAlgValuesSupported!);
        Assert.DoesNotContain("HS256", discovery.DPoPSigningAlgValuesSupported!);
        Assert.DoesNotContain("none", discovery.DPoPSigningAlgValuesSupported!);
    }

    // ───────────────────────────────────────────────────────────────────────
    // Flow drivers
    // ───────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Drives PAR -> /authorize -> /token with optional DPoP proofs on PAR and token.
    /// Returns the parsed token response on the success path; throws on any non-success
    /// HTTP status -- callers expecting a token-endpoint error use the *ExpectingError*
    /// variant.
    /// </summary>
    private static async Task<JsonObject> DriveParAuthorizeTokenAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string? parProof,
        string? tokenProof)
    {
        var (verifier, challenge) = GeneratePkcePair();

        var parResponse = await SendParAsync(client, discovery, clientId, challenge, parProof);
        Assert.True(parResponse.IsSuccessStatusCode,
            $"PAR failed: {(int)parResponse.StatusCode} {await parResponse.Content.ReadAsStringAsync()}");
        var parBody = JsonNode.Parse(await parResponse.Content.ReadAsStringAsync())!.AsObject();
        var requestUri = parBody[WireParameters.RequestUri]!.GetValue<string>();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [WireParameters.ClientId] = clientId,
            [WireParameters.RequestUri] = requestUri,
        });

        var tokenResponse = await SendTokenAsync(client, discovery, clientId, code, verifier, tokenProof);
        Assert.True(tokenResponse.IsSuccessStatusCode,
            $"/token failed: {(int)tokenResponse.StatusCode} {await tokenResponse.Content.ReadAsStringAsync()}");
        return JsonNode.Parse(await tokenResponse.Content.ReadAsStringAsync())!.AsObject();
    }

    /// <summary>
    /// Same flow as <see cref="DriveParAuthorizeTokenAsync"/> but expects the /token
    /// call to fail; returns the error code from the response body. PAR and /authorize
    /// are still expected to succeed -- if they don't, the test fails loudly so the
    /// scenario doesn't silently green-pass on a wrong-stage rejection.
    /// </summary>
    private static async Task<string> DriveParAuthorizeTokenExpectingErrorAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string? parProof,
        string? tokenProof)
    {
        var (verifier, challenge) = GeneratePkcePair();

        var parResponse = await SendParAsync(client, discovery, clientId, challenge, parProof);
        Assert.True(parResponse.IsSuccessStatusCode,
            $"PAR unexpectedly failed: {(int)parResponse.StatusCode} {await parResponse.Content.ReadAsStringAsync()}");
        var parBody = JsonNode.Parse(await parResponse.Content.ReadAsStringAsync())!.AsObject();
        var requestUri = parBody[WireParameters.RequestUri]!.GetValue<string>();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [WireParameters.ClientId] = clientId,
            [WireParameters.RequestUri] = requestUri,
        });

        var tokenResponse = await SendTokenAsync(client, discovery, clientId, code, verifier, tokenProof);
        Assert.False(tokenResponse.IsSuccessStatusCode,
            $"/token unexpectedly succeeded: {await tokenResponse.Content.ReadAsStringAsync()}");
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        var body = JsonNode.Parse(await tokenResponse.Content.ReadAsStringAsync())!.AsObject();
        return body[WireParameters.Error]!.GetValue<string>();
    }

    private static async Task<HttpResponseMessage> SendParAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string challenge,
        string? proofJwt)
    {
        var form = new Dictionary<string, string>
        {
            [WireParameters.ClientId] = clientId,
            [WireParameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [WireParameters.ResponseType] = "code",
            [WireParameters.RedirectUri] = TestConstants.RedirectUri,
            [WireParameters.Scope] = "openid",
            [WireParameters.State] = Guid.NewGuid().ToString("N"),
            [WireParameters.Nonce] = Guid.NewGuid().ToString("N"),
            [WireParameters.CodeChallenge] = challenge,
            [WireParameters.CodeChallengeMethod] = "S256",
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.PushedAuthorizationRequestEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        if (proofJwt is not null)
            request.WithDPoPHeader(proofJwt);
        return await client.SendAsync(request);
    }

    /// <summary>
    /// Drives PAR -> /authorize -> /token with a token-endpoint DPoP proof signed by
    /// <paramref name="proofKey"/>, asserts the resulting access token is DPoP-bound to
    /// that key, and returns the raw access_token string. UserInfo scenarios start here.
    /// </summary>
    private static async Task<string> ObtainDPoPBoundAccessTokenAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        DPoPProofGenerator proofKey)
    {
        var tokenProof = proofKey.BuildProof("POST", new Uri(discovery.TokenEndpoint));
        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null, tokenProof: tokenProof);
        AssertDPoPBound(tokenResponse, expectedThumbprint: proofKey.Thumbprint);
        return tokenResponse[WireParameters.AccessToken]!.GetValue<string>();
    }

    /// <summary>
    /// Sends a GET to /userinfo with the given access token and optional DPoP proof,
    /// presented under the supplied <paramref name="scheme"/> (DPoP or Bearer). Returns
    /// the raw response so callers can inspect both status and headers.
    /// </summary>
    private static async Task<HttpResponseMessage> SendUserInfoAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string accessToken,
        string? proofJwt,
        string scheme)
    {
        Assert.NotNull(discovery.UserInfoEndpoint);
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, accessToken);
        if (proofJwt is not null)
            request.WithDPoPHeader(proofJwt);
        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> SendTokenAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string code,
        string verifier,
        string? proofJwt)
    {
        var form = new Dictionary<string, string>
        {
            [WireParameters.GrantType] = "authorization_code",
            [WireParameters.Code] = code,
            [WireParameters.RedirectUri] = TestConstants.RedirectUri,
            [WireParameters.CodeVerifier] = verifier,
            [WireParameters.ClientId] = clientId,
            [WireParameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        if (proofJwt is not null)
            request.WithDPoPHeader(proofJwt);
        return await client.SendAsync(request);
    }

    // ───────────────────────────────────────────────────────────────────────
    // Assertions
    // ───────────────────────────────────────────────────────────────────────

    private static void AssertDPoPBound(JsonObject tokenResponse, string expectedThumbprint)
    {
        Assert.Equal(TokenTypes.DPoP, tokenResponse["token_type"]!.GetValue<string>());

        // RFC 9449 §6: the issued access token carries cnf.jkt = the proof key's JWK thumbprint.
        var accessToken = tokenResponse[WireParameters.AccessToken]!.GetValue<string>();
        var payload = DecodeJwtPayload(accessToken);
        var cnf = payload["cnf"]?.AsObject();
        Assert.NotNull(cnf);
        var jkt = cnf!["jkt"]?.GetValue<string>();
        Assert.Equal(expectedThumbprint, jkt);
    }

    private static void AssertBearer(JsonObject tokenResponse)
    {
        Assert.Equal(TokenTypes.Bearer, tokenResponse["token_type"]!.GetValue<string>());
        var accessToken = tokenResponse[WireParameters.AccessToken]!.GetValue<string>();
        var payload = DecodeJwtPayload(accessToken);
        Assert.Null(payload["cnf"]);
    }
}
