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
using Microsoft.AspNetCore.Http;
using Abblix.Oidc.Server.Model;
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
            tokenProof: proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint));

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
            tokenProof: proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint));

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

        var parProof = proofKey.BuildProof(HttpMethods.Post, discovery.PushedAuthorizationRequestEndpoint!);
        var tokenProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);

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

        var parProof = parKey.BuildProof(HttpMethods.Post, discovery.PushedAuthorizationRequestEndpoint!);
        var tokenProof = tokenKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);

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

        var parProof = parKey.BuildProof(HttpMethods.Post, discovery.PushedAuthorizationRequestEndpoint!);

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
        var sharedProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);

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
    // Wire-level error contract — proof validator failures surface as
    // 400 invalid_dpop_proof end-to-end. The validator's failure taxonomy is
    // exhaustively covered by ProofValidatorTests at the unit level; the two
    // tests here pin the contract that those failures actually reach the wire
    // unchanged through DPoPTokenEndpointValidator and the response formatter.
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Token_endpoint_rejects_proof_whose_htm_does_not_match_the_request_method()
    {
        // RFC 9449 §4.3 step 8: htm MUST match the HTTP method byte-exact. Mint a
        // proof claiming GET, then POST it to /token — the validator should reject
        // and the wire response should carry error=invalid_dpop_proof at HTTP 400.
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var proofForWrongMethod = proofKey.BuildProof(HttpMethods.Get, discovery.TokenEndpoint);

        var error = await DriveParAuthorizeTokenExpectingErrorAsync(
            client, discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: proofForWrongMethod);

        Assert.Equal(ErrorCodes.InvalidDPoPProof, error);
    }

    [Fact]
    public async Task Token_endpoint_rejects_proof_with_corrupted_signature()
    {
        // RFC 9449 §4.3 step 6: signature MUST verify. Mint a valid proof then
        // flip a byte in the signature segment; downstream signature verification
        // fails and the validator returns invalid_dpop_proof — pin the wire shape.
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var validProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var corrupted = CorruptSignatureSegment(validProof);

        var error = await DriveParAuthorizeTokenExpectingErrorAsync(
            client, discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: corrupted);

        Assert.Equal(ErrorCodes.InvalidDPoPProof, error);
    }

    /// <summary>
    /// Tampers with the first character of a JWS's signature segment. The proof
    /// otherwise remains structurally valid (3 dot-separated base64url parts);
    /// only the bytes that signature verification reads change, so the failure
    /// must come from the crypto check rather than from a structural pre-screen.
    /// </summary>
    private static string CorruptSignatureSegment(string proofJws)
    {
        var parts = proofJws.Split('.');
        Assert.Equal(3, parts.Length);
        var sig = parts[2];
        var firstChar = sig[0];
        // Swap with a different valid base64url character to keep the JWS parseable.
        parts[2] = (firstChar == 'A' ? 'B' : 'A') + sig[1..];
        return string.Join('.', parts);
    }

    // ───────────────────────────────────────────────────────────────────────
    // Refresh token rebinding (RFC 9449 §5)
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_with_same_dpop_key_yields_new_token_bound_to_same_jkt()
    {
        // RFC 9449 §5: when refreshing a DPoP-bound access token, the new token MUST be
        // bound to the same key as the previous one. Abblix enforces this via the §10
        // carry-over mechanism — the original grant's ProofKeyThumbprint is committed on
        // the refresh token and DPoPTokenEndpointValidator rejects any proof key drift.
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var initial = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint),
            scope: $"{Scopes.OpenId} {Scopes.OfflineAccess}");
        AssertDPoPBound(initial, expectedThumbprint: proofKey.Thumbprint);
        var refreshToken = initial[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        // Fresh proof (new jti, current iat) signed by the SAME keypair.
        var refreshProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPOpportunisticClientId, refreshProof);

        var raw = await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(refreshHttp.IsSuccessStatusCode,
            $"/token refresh failed: {(int)refreshHttp.StatusCode} {raw}");
        var refreshBody = JsonNode.Parse(raw)!.AsObject();
        AssertDPoPBound(refreshBody, expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Confidential_client_can_rebind_to_new_dpop_key_on_refresh()
    {
        // RFC 9449 §5 explicit carve-out: «Refresh tokens issued to confidential
        // clients (those having established authentication credentials with the
        // authorization server) are not bound to the DPoP proof public key because
        // they are already sender-constrained with a different existing mechanism»
        // (client authentication). The AS therefore accepts a fresh DPoP key on
        // refresh and binds the new access token to it — a confidential client may
        // rotate keys without re-running the auth-code dance. The strict
        // same-key-MUST rule of §5 applies only to PUBLIC clients; a no-secret
        // seeded client is out of scope for this slice.
        using var originalKey = new DPoPProofGenerator();
        using var rotatedKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var initial = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: originalKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint),
            scope: Scopes.OpenId + " " + Scopes.OfflineAccess);
        AssertDPoPBound(initial, expectedThumbprint: originalKey.Thumbprint);
        var refreshToken = initial[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        // Refresh with a freshly rotated key — must succeed and the new access token
        // must be bound to the rotated key (not the original one).
        var rotatedProof = rotatedKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPOpportunisticClientId, rotatedProof);

        var raw = await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(refreshHttp.IsSuccessStatusCode,
            $"/token refresh failed: {(int)refreshHttp.StatusCode} {raw}");
        var refreshBody = JsonNode.Parse(raw)!.AsObject();
        AssertDPoPBound(refreshBody, expectedThumbprint: rotatedKey.Thumbprint);
    }

    [Fact]
    public async Task Public_client_refresh_with_same_dpop_key_yields_new_token_bound_to_same_jkt()
    {
        // RFC 9449 §5: public clients (token_endpoint_auth_method = none) lack a shared
        // secret, so DPoP is the sole sender-constraint. Same-key MUST therefore be
        // enforced on refresh. Abblix carries the thumbprint forward via the §10
        // PAR-time commitment path; a proof on the PAR request commits dpop_jkt into
        // the stored authorization request, the auth code restores it, and refresh
        // tokens for public clients keep it (vs. confidential clients which strip).
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var parProof = proofKey.BuildProof(HttpMethods.Post, discovery.PushedAuthorizationRequestEndpoint!);
        var tokenProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var initial = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: TestConstants.DPoPPublicClientId,
            parProof: parProof,
            tokenProof: tokenProof,
            scope: Scopes.OpenId + " " + Scopes.OfflineAccess,
            clientSecret: null);
        AssertDPoPBound(initial, expectedThumbprint: proofKey.Thumbprint);
        var refreshToken = initial[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        var refreshProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPPublicClientId, refreshProof, clientSecret: null);

        var raw = await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(refreshHttp.IsSuccessStatusCode,
            $"/token refresh failed: {(int)refreshHttp.StatusCode} {raw}");
        var refreshBody = JsonNode.Parse(raw)!.AsObject();
        AssertDPoPBound(refreshBody, expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Public_client_non_par_refresh_with_same_dpop_key_yields_new_token_bound_to_same_jkt()
    {
        // RFC 9449 §5 applies regardless of how the initial token was obtained — a
        // proof at /token alone (no PAR commitment) is enough to bind the access
        // token, and the binding MUST flow through to the refresh token. Pins the
        // TokenRequestProcessor fix: public-flow refreshContext sources its thumbprint
        // from authContext (live proof) rather than from the un-evaluated grant
        // context (which is null without PAR).
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var initial = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: TestConstants.DPoPPublicClientId,
            parProof: null,
            tokenProof: proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint),
            scope: Scopes.OpenId + " " + Scopes.OfflineAccess,
            clientSecret: null);
        AssertDPoPBound(initial, expectedThumbprint: proofKey.Thumbprint);
        var refreshToken = initial[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        var refreshProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPPublicClientId, refreshProof, clientSecret: null);

        var raw = await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(refreshHttp.IsSuccessStatusCode,
            $"/token refresh failed: {(int)refreshHttp.StatusCode} {raw}");
        AssertDPoPBound(JsonNode.Parse(raw)!.AsObject(), expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Public_client_non_par_refresh_with_different_dpop_key_is_rejected_per_rfc9449_section5()
    {
        // Regression pin for the TokenRequestProcessor fix. Before the fix the public
        // refresh path sourced refreshContext from request.AuthorizedGrant.Context,
        // which carried no ProofKeyThumbprint for non-PAR flows; the validator's
        // committed-vs-presented compare then short-circuited (committed = null) and
        // a rotated key was silently accepted — a §5 MUST violation. Post-fix the
        // refresh JWT carries cnf.jkt from authContext (live proof's thumbprint), so
        // the next refresh's mismatched proof is caught.
        using var originalKey = new DPoPProofGenerator();
        using var attackerKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var initial = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: TestConstants.DPoPPublicClientId,
            parProof: null,
            tokenProof: originalKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint),
            scope: Scopes.OpenId + " " + Scopes.OfflineAccess,
            clientSecret: null);
        AssertDPoPBound(initial, expectedThumbprint: originalKey.Thumbprint);
        var refreshToken = initial[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        var attackerProof = attackerKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPPublicClientId, attackerProof, clientSecret: null);

        Assert.Equal(HttpStatusCode.BadRequest, refreshHttp.StatusCode);
        var body = JsonNode.Parse(await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidDPoPProof, body["error"]!.GetValue<string>());
    }

    [Fact]
    public async Task Public_client_refresh_with_different_dpop_key_is_rejected_per_rfc9449_section5()
    {
        // RFC 9449 §5 MUST for public clients: «such a client MUST present a DPoP proof
        // for the same key that was used to obtain the refresh token each time that
        // refresh token is used». A rotated key on refresh is the canonical theft
        // scenario the constraint exists to close — without a shared secret, the proof
        // key is the only thing tying the holder to the original grant. Commitment is
        // anchored at PAR (Abblix §10 carry-over path); a proof on PAR makes the AS
        // pin dpop_jkt onto the stored authorization request, and the public-client
        // refresh path preserves the binding through to subsequent token requests.
        using var originalKey = new DPoPProofGenerator();
        using var attackerKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var parProof = originalKey.BuildProof(HttpMethods.Post, discovery.PushedAuthorizationRequestEndpoint!);
        var tokenProof = originalKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var initial = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: TestConstants.DPoPPublicClientId,
            parProof: parProof,
            tokenProof: tokenProof,
            scope: Scopes.OpenId + " " + Scopes.OfflineAccess,
            clientSecret: null);
        AssertDPoPBound(initial, expectedThumbprint: originalKey.Thumbprint);
        var refreshToken = initial[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        var attackerProof = attackerKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPPublicClientId, attackerProof, clientSecret: null);

        Assert.Equal(HttpStatusCode.BadRequest, refreshHttp.StatusCode);
        var body = JsonNode.Parse(await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidDPoPProof, body["error"]!.GetValue<string>());
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
            HttpMethods.Get, discovery.UserInfoEndpoint!, accessToken: accessToken);

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
        var unboundAccessToken = tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        // Attach a syntactically valid proof to make sure the rejection is about the
        // token's binding state, not about a missing proof header.
        using var proofKey = new DPoPProofGenerator();
        var proof = proofKey.BuildProof(
            HttpMethods.Get, discovery.UserInfoEndpoint!, accessToken: unboundAccessToken);

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
            HttpMethods.Get, discovery.UserInfoEndpoint!, accessToken: accessToken);

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
        string? tokenProof,
        string scope = Scopes.OpenId,
        string? clientSecret = TestConstants.ConfidentialClientSecret)
    {
        var (verifier, challenge) = GeneratePkcePair();

        var parResponse = await SendParAsync(client, discovery, clientId, challenge, parProof, scope, clientSecret);
        Assert.True(parResponse.IsSuccessStatusCode,
            $"PAR failed: {(int)parResponse.StatusCode} {await parResponse.Content.ReadAsStringAsync()}");
        var parBody = JsonNode.Parse(await parResponse.Content.ReadAsStringAsync())!.AsObject();
        var requestUri = parBody[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.RequestUri] = requestUri,
        });

        var tokenResponse = await SendTokenAsync(client, discovery, clientId, code, verifier, tokenProof, clientSecret);
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
        var requestUri = parBody[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.RequestUri] = requestUri,
        });

        var tokenResponse = await SendTokenAsync(client, discovery, clientId, code, verifier, tokenProof);
        Assert.False(tokenResponse.IsSuccessStatusCode,
            $"/token unexpectedly succeeded: {await tokenResponse.Content.ReadAsStringAsync()}");
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        var body = JsonNode.Parse(await tokenResponse.Content.ReadAsStringAsync())!.AsObject();
        return body["error"]!.GetValue<string>();
    }

    private static async Task<HttpResponseMessage> SendParAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string challenge,
        string? proofJwt,
        string scope = Scopes.OpenId,
        string? clientSecret = TestConstants.ConfidentialClientSecret)
    {
        var form = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = scope,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        };
        // Public clients (TokenEndpointAuthMethod = none) supply no client_secret.
        if (clientSecret is not null)
            form[ClientRequest.Parameters.ClientSecret] = clientSecret;

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
        var tokenProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null, tokenProof: tokenProof);
        AssertDPoPBound(tokenResponse, expectedThumbprint: proofKey.Thumbprint);
        return tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
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

    /// <summary>
    /// Sends a refresh_token grant request with a DPoP proof. The refresh token is
    /// taken from the previous token response; the proof must be signed by the same
    /// keypair the original access token was bound to (RFC 9449 §5 + §10 carry-over).
    /// </summary>
    private static async Task<HttpResponseMessage> SendRefreshAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string refreshToken,
        string clientId,
        string proofJwt,
        string? clientSecret = TestConstants.ConfidentialClientSecret)
    {
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
            [AuthorizationRequest.Parameters.ClientId] = clientId,
        };
        if (clientSecret is not null)
            form[ClientRequest.Parameters.ClientSecret] = clientSecret;
        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        request.WithDPoPHeader(proofJwt);
        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> SendTokenAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string code,
        string verifier,
        string? proofJwt,
        string? clientSecret = TestConstants.ConfidentialClientSecret)
    {
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = clientId,
        };
        if (clientSecret is not null)
            form[ClientRequest.Parameters.ClientSecret] = clientSecret;

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
        Assert.Equal(TokenTypes.DPoP, tokenResponse[BackChannelTokenPushRequest.Parameters.TokenType]!.GetValue<string>());

        // RFC 9449 §6: the issued access token carries cnf.jkt = the proof key's JWK thumbprint.
        var accessToken = tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var payload = DecodeJwtPayload(accessToken);
        var cnf = payload["cnf"]?.AsObject();
        Assert.NotNull(cnf);
        var jkt = cnf!["jkt"]?.GetValue<string>();
        Assert.Equal(expectedThumbprint, jkt);
    }

    private static void AssertBearer(JsonObject tokenResponse)
    {
        Assert.Equal(TokenTypes.Bearer, tokenResponse[BackChannelTokenPushRequest.Parameters.TokenType]!.GetValue<string>());
        var accessToken = tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var payload = DecodeJwtPayload(accessToken);
        Assert.Null(payload["cnf"]);
    }
}
