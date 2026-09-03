// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9449 section 9 resource access (UserInfo as the protected resource) for DPoP-bound
/// access tokens, end-to-end against the test OIDC provider. Covers the matching-proof
/// success path, the section 7.2 downgrade-to-Bearer rejection, Abblix's reject-unbound-as-DPoP
/// posture, and proof-key mismatch. Token-endpoint binding (section 6) lives in
/// <see cref="DPoPTests"/> and refresh rebinding (section 5) in <see cref="DPoPRefreshTests"/>;
/// the three share <see cref="DPoPTestBase"/>.
/// </summary>
public class DPoPUserInfoTests(TestFactory factory) : DPoPTestBase(factory)
{
    [Fact]
    public async Task UserInfo_with_dpop_bound_token_and_matching_proof_succeeds()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var accessToken = await ObtainDPoPBoundAccessTokenAsync(client, discovery, proofKey);

        // RFC 9449 section 7.1: proof must carry ath = base64url(sha256(access_token)).
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
        // RFC 9449 section 7.2: "such a protected resource MUST reject a DPoP-bound access
        // token received as a bearer token". The check exists to close the downgrade-
        // to-Bearer attack surface. RFC 9449 section 7.1 also asks the response to carry a
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
        // Abblix-side defensive posture: RFC 9449 section 7.1's check list "the public key of
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

        // Proof signed with a different key - the attacker stole the token but lacks the
        // private key the token was bound to. The AS computes the proof's jkt and finds
        // it doesn't match the token's cnf.jkt. RFC 9449 section 7.1: the resource server SHOULD
        // accompany the 401 with a WWW-Authenticate: DPoP challenge so the client knows
        // which scheme to use on retry.
        var attackerProof = attackerKey.BuildProof(
            HttpMethods.Get, discovery.UserInfoEndpoint!, accessToken: accessToken);

        var response = await SendUserInfoAsync(
            client, discovery, accessToken, attackerProof, scheme: TokenTypes.DPoP);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == TokenTypes.DPoP);
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
}
